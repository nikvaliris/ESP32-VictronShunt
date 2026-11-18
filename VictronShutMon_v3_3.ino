#include <Arduino.h>
#include <SPI.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <TFT_eSPI.h>
#include <XPT2046_Touchscreen.h>
#include <NimBLEDevice.h>
#include "mbedtls/aes.h"
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

// ==========================================
// 1. HARDWARE PIN DEFINITIONS (ESP32-2432S028R CYD)
// ==========================================
#define TFT_BL_PIN   21
#define TFT_CS_PIN   15
#define SD_CS_PIN     5

// Touch controller on separate VSPI pins
#define XPT2046_IRQ  36
#define XPT2046_MOSI 32
#define XPT2046_MISO 39
#define XPT2046_CLK  25
#define XPT2046_CS   33

// ==========================================
// 2. GLOBAL OBJECTS & CONFIGURATION
// ==========================================
TFT_eSPI tft = TFT_eSPI();
SPIClass touchSPI = SPIClass(VSPI);
XPT2046_Touchscreen ts(XPT2046_CS, XPT2046_IRQ);

WebServer server(80);
Preferences prefs;

String victronKeyHex = "";
String apPassword    = "Victron123";
String wifiSSID      = "";
String wifiPass      = "";

uint8_t* aesKey  = (uint8_t*)calloc(16, 1);
bool hasValidKey = false;
bool isApMode    = false;
bool showDebug   = false;
bool screenOn    = true; // Tracks TFT backlight state

// ==========================================
// 3. LIVE & HISTORICAL SHUNT DATA
// ==========================================
struct ShuntData {
  float voltage       = 0.0f;
  float current       = 0.0f;
  float power         = 0.0f;
  float soc           = 0.0f;
  float consumedAh    = 0.0f;
  int   ttgMinutes    = -1;
  uint16_t alarm      = 0;
  bool  valid         = false;
  unsigned long lastUpdateMs = 0;
};

volatile bool newDataAvailable = false;
ShuntData liveData;
ShuntData sharedData;
portMUX_TYPE dataMux = portMUX_INITIALIZER_UNLOCKED;

// On-Screen BLE Debug Counters
volatile uint32_t dbgTotalBlePkts = 0;
volatile uint32_t dbgVictronPkts  = 0;
char* dbgLastMsg = (char*)calloc(64, 1);

// 60-point circular buffer (1 sample every 60s = 1 hour rolling SOC history)
#define HISTORY_LEN 60
float* histSoc   = (float*)calloc(HISTORY_LEN, sizeof(float));
int    histCount = 0;
unsigned long lastHistSampleMs = 0;

// UI State
enum ScreenPage { PAGE_MAIN = 0, PAGE_GRAPH = 1, PAGE_INFO = 2 };
ScreenPage currentPage = PAGE_MAIN;
unsigned long lastTouchMs     = 0;
unsigned long lastUiRefreshMs = 0;
uint8_t animStep = 0;
unsigned long lastAnimMs = 0;

// ==========================================
// 4. HELPER UTILITIES
// ==========================================
bool hexToBytes(const String& hexStr, uint8_t* outBytes, size_t expectedLen) {
  String clean = "";
  for (size_t i = 0; i < hexStr.length(); i++) {
    char c = hexStr.charAt(i);
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
      clean += (char)tolower(c);
    }
  }

  if (clean.length() != expectedLen * 2) {
    snprintf(dbgLastMsg, 64, "Key len=%d (need 32 hex)", clean.length());
    return false;
  }

  for (size_t i = 0; i < expectedLen; i++) {
    char c1 = clean.charAt(i * 2);
    char c2 = clean.charAt(i * 2 + 1);
    uint8_t hi = (c1 >= '0' && c1 <= '9') ? (c1 - '0') : (c1 - 'a' + 10);
    uint8_t lo = (c2 >= '0' && c2 <= '9') ? (c2 - '0') : (c2 - 'a' + 10);
    *(outBytes + i) = (hi << 4) | lo;
  }
  return true;
}

String htmlEscape(const String& str) {
  String out = str;
  out.replace("&", "&amp;");
  out.replace("<", "&lt;");
  out.replace(">", "&gt;");
  out.replace("\"", "&quot;");
  out.replace("'", "&#39;");
  return out;
}

String formatTTG(int mins) {
  if (mins < 0 || mins >= 65535) return "Infinite";
  int hrs = mins / 60;
  int rem = mins % 60;
  if (hrs >= 24) {
    int days = hrs / 24;
    hrs = hrs % 24;
    return String(days) + "d " + String(hrs) + "h";
  }
  return String(hrs) + "h " + String(rem) + "m";
}

// ==========================================
// 5. VICTRON BLE DECRYPTION & SCANNER
// ==========================================
void parseVictronManufacturerData(const uint8_t* data, size_t len) {
  dbgTotalBlePkts++;

  if (len < 25) return;
  // Check Victron Company ID 0x02E1 (little-endian: 0xE1, 0x02)
  if (*(data + 0) != 0xE1 || *(data + 1) != 0x02) return;

  dbgVictronPkts++;

  if (!hasValidKey) {
    snprintf(dbgLastMsg, 64, "Victron seen! Key invalid/empty");
    return;
  }

  if (*(data + 2) != 0x10) {
    snprintf(dbgLastMsg, 64, "Victron mode 0x%02X (not 0x10)", *(data + 2));
    return;
  }

  // Byte 6 is Record Type (0x02 = Battery Monitor / SmartShunt)
  uint8_t recordType = *(data + 6);
  if (recordType != 0x02) {
    snprintf(dbgLastMsg, 64, "Victron type 0x%02X (not Shunt)", recordType);
    return;
  }

  // Bytes 7..8 = 16-bit Nonce; Byte 9 = First byte of AES key
  uint16_t nonce = (uint16_t)(*(data + 7)) | ((uint16_t)(*(data + 8)) << 8);
  uint8_t keyCheckByte = *(data + 9);
  if (keyCheckByte != *(aesKey + 0)) {
    snprintf(dbgLastMsg, 64, "BAD KEY: pkt %02X != cfg %02X", keyCheckByte, *(aesKey + 0));
    return;
  }

  // Encrypted payload starts at byte 10
  const uint8_t* encPayload = data + 10;
  size_t encLen = len - 10;
  if (encLen > 32) encLen = 32;

  uint8_t* nonceCounter = (uint8_t*)calloc(16, 1);
  *(nonceCounter + 0) = nonce & 0xFF;
  *(nonceCounter + 1) = (nonce >> 8) & 0xFF;

  uint8_t* streamBlock = (uint8_t*)calloc(16, 1);
  uint8_t* dec         = (uint8_t*)calloc(32, 1);
  size_t ncOff = 0;

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, aesKey, 128);
  mbedtls_aes_crypt_ctr(&aes, encLen, &ncOff, nonceCounter, streamBlock, encPayload, dec);
  mbedtls_aes_free(&aes);

  free(nonceCounter);
  free(streamBlock);

  if (encLen < 15) {
    free(dec);
    return;
  }

  // Bytes 0..5: Time-To-Go, Battery Voltage, and Alarm flags
  uint16_t ttgRaw   = (uint16_t)(*(dec + 0)) | ((uint16_t)(*(dec + 1)) << 8);
  int16_t  voltRaw  = (int16_t)((uint16_t)(*(dec + 2)) | ((uint16_t)(*(dec + 3)) << 8));
  uint16_t alarmRaw = (uint16_t)(*(dec + 4)) | ((uint16_t)(*(dec + 5)) << 8);

  // Unpack bytes 8..14 (56 bits) as a single 64-bit little-endian integer
  uint64_t packed56 = 0;
  for (int i = 0; i < 7; i++) {
    packed56 |= ((uint64_t)(*(dec + 8 + i))) << (i * 8);
  }

  // Bits 0..1 of packed56 = 2-bit Aux Input type (skip with >> 2)
  // 1. Bits 2..23 (22 bits): Signed Current in units of 1 mA (0.001 A)
  int32_t currRaw = (int32_t)((packed56 >> 2) & 0x3FFFFFULL);
  if (currRaw & 0x200000) currRaw |= 0xFFC00000;

  // 2. Bits 24..43 (20 bits): Consumed Ah in units of 0.1 Ah
  uint32_t ahRaw = (uint32_t)((packed56 >> 24) & 0xFFFFFULL);

  // 3. Bits 44..53 (10 bits): State of Charge in units of 0.1%
  uint16_t socRaw = (uint16_t)((packed56 >> 44) & 0x3FFULL);

  free(dec);

  float v   = voltRaw * 0.01f;
  float a   = currRaw * 0.001f;
  float p   = v * a;
  float soc = (socRaw <= 1000) ? (socRaw * 0.1f) : 0.0f;
  float ah  = (ahRaw == 0xFFFFF) ? 0.0f : -(ahRaw * 0.1f);

  snprintf(dbgLastMsg, 64, "OK! V=%.2fV A=%.2fA SOC=%.1f%%", v, a, soc);

  portENTER_CRITICAL(&dataMux);
  sharedData.voltage      = v;
  sharedData.current      = a;
  sharedData.power        = p;
  sharedData.soc          = soc;
  sharedData.consumedAh   = ah;
  sharedData.ttgMinutes   = (ttgRaw == 0xFFFF) ? -1 : (int)ttgRaw;
  sharedData.alarm        = alarmRaw;
  sharedData.valid        = true;
  sharedData.lastUpdateMs = millis();
  newDataAvailable        = true;
  portEXIT_CRITICAL(&dataMux);
}

class VictronScanCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* advertisedDevice) override {
    dbgTotalBlePkts++;
    int mfgCount = advertisedDevice->getManufacturerDataCount();
    for (int i = 0; i < mfgCount; i++) {
      std::string mfg = advertisedDevice->getManufacturerData(i);
      parseVictronManufacturerData((const uint8_t*)mfg.data(), mfg.size());
    }
  }
};

// ==========================================
// 6. TFT DISPLAY RENDERING (320x240 LANDSCAPE)
// ==========================================
void drawTopBar(const char* title) {
  tft.fillRect(0, 0, 320, 28, 0x10A2);

  // Top-Left Screen Off Button (x: 2..44, y: 3..25)
  tft.fillRoundRect(2, 3, 42, 22, 4, 0x3186);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(TFT_WHITE, 0x3186);
  tft.drawString("OFF", 23, 14, 1);

  // Title shifted right to clear the OFF button
  tft.setTextDatum(ML_DATUM);
  tft.setTextColor(TFT_CYAN, 0x10A2);
  tft.drawString(title, 50, 14, 2);

  // Connection Status Badge on Right
  tft.setTextDatum(MR_DATUM);
  if (!hasValidKey) {
    tft.setTextColor(TFT_YELLOW, 0x10A2);
    tft.drawString("NO KEY", 314, 14, 2);
  } else if (liveData.valid && (millis() - liveData.lastUpdateMs < 15000)) {
    tft.setTextColor(TFT_GREEN, 0x10A2);
    tft.drawString("LIVE", 314, 14, 2);
  } else {
    tft.setTextColor(TFT_ORANGE, 0x10A2);
    tft.drawString("SCAN...", 314, 14, 2);
  }
}

void drawNavButtons() {
  int y = 206;
  int h = 34;
  tft.drawFastHLine(0, y - 1, 320, TFT_DARKGREY);

  const char* label0 = "LIVE";
  const char* label1 = "HISTORY";
  const char* label2 = "NETWORK";

  for (int i = 0; i < 3; i++) {
    int x = i * 107;
    int w = (i == 2) ? 106 : 107;
    uint16_t bg = (currentPage == i) ? 0xD813 : 0x18E3;
    uint16_t fg = (currentPage == i) ? TFT_WHITE : TFT_LIGHTGREY;
    tft.fillRect(x, y, w, h, bg);
    if (i > 0) tft.drawFastVLine(x, y, h, TFT_BLACK);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(fg, bg);
    const char* lbl = (i == 0) ? label0 : ((i == 1) ? label1 : label2);
    tft.drawString(lbl, x + w / 2, y + h / 2, 2);
  }
}

// Draws battery icon with SOC fill level (Green/Amber/Red) + Animated Flow Chevrons
void drawBatteryGraphic(int x, int y, float soc, float current, bool valid, uint8_t step) {
  int w = 44;
  int h = 22;

  // Clear battery + arrow zone cleanly before redrawing
  tft.fillRect(x - 2, y - 1, w + 8, h + 16, TFT_BLACK);

  // Battery outer casing + positive terminal nub on right
  tft.drawRoundRect(x, y, w, h, 3, TFT_WHITE);
  tft.fillRect(x + w, y + 6, 4, h - 12, TFT_WHITE);

  if (!valid) return;

  float clampedSoc = constrain(soc, 0.0f, 100.0f);
  int fillW = (int)round(((w - 4) * clampedSoc) / 100.0f);

  // Colour coding: Green (>50%), Amber (21-50%), Red (<=20%)
  uint16_t levelColor = TFT_GREEN;
  if (clampedSoc <= 20.0f) {
    levelColor = TFT_RED;
  } else if (clampedSoc <= 50.0f) {
    levelColor = 0xFD20; // Bright Amber
  }

  if (fillW > 0) {
    tft.fillRect(x + 2, y + 2, fillW, h - 4, levelColor);
  }

  // Animated 3-chevron flow bar below the battery icon
  int ay = y + h + 8;
  if (current > 0.05f) {
    // CHARGING: Green chevrons moving INWARD (left-to-right toward battery)
    for (uint8_t i = 0; i < 3; i++) {
      int cx = x + 6 + (i * 13);
      uint16_t col = (i == step) ? TFT_GREEN : 0x0320; // Bright leading chevron + dim trail
      tft.drawLine(cx - 4, ay - 4, cx + 1, ay, col);
      tft.drawLine(cx - 4, ay + 4, cx + 1, ay, col);
      tft.drawLine(cx - 3, ay - 4, cx + 2, ay, col);
      tft.drawLine(cx - 3, ay + 4, cx + 2, ay, col);
    }
  } else if (current < -0.05f) {
    // DISCHARGING: Amber chevrons moving OUTWARD (right-to-left away from battery)
    for (uint8_t i = 0; i < 3; i++) {
      int cx = x + 36 - (i * 13);
      uint16_t col = (i == step) ? 0xFD20 : 0x4100; // Bright leading chevron + dim trail
      tft.drawLine(cx + 4, ay - 4, cx - 1, ay, col);
      tft.drawLine(cx + 4, ay + 4, cx - 1, ay, col);
      tft.drawLine(cx + 3, ay - 4, cx - 2, ay, col);
      tft.drawLine(cx + 3, ay + 4, cx - 2, ay, col);
    }
  }
}
void drawMainPageFull() {
tft.fillScreen(TFT_BLACK);
drawTopBar("VICTRON SHUNT");
int boxH  = showDebug ? 72 : 78;
int row2Y = showDebug ? 110 : 118;
int box2H = showDebug ? 74 : 80;
tft.drawRoundRect(6, 34, 150, boxH, 6, 0x2945);
tft.drawRoundRect(164, 34, 150, boxH, 6, 0x2945);
tft.drawRoundRect(6, row2Y, 150, box2H, 6, 0x2945);
tft.drawRoundRect(164, row2Y, 150, box2H, 6, 0x2945);
tft.setTextDatum(TL_DATUM);
tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
tft.drawString("STATE OF CHARGE", 14, 40, 1);
tft.drawString("BATTERY VOLTAGE", 172, 40, 1);
tft.drawString("CURRENT", 14, row2Y + 6, 1);
tft.drawString("POWER / TTG", 172, row2Y + 6, 1);
drawNavButtons();
}
void updateMainValues() {
  if (!screenOn) return;

  drawTopBar("VICTRON SHUNT");

  int val1Y = showDebug ? 74 : 78;
  int row2Y = showDebug ? 110 : 118;
  int val2Y = showDebug ? 152 : 162;
  int pwrY  = showDebug ? 144 : 154;
  int ttgY  = showDebug ? 170 : 182;

  // 1. State of Charge (Number on left + Animated Battery Graphic on right)
  tft.fillRect(10, 52, 82, 48, TFT_BLACK);
  tft.setTextDatum(MC_DATUM);
  uint16_t socColor = TFT_GREEN;
  if (liveData.soc <= 20.0f) socColor = TFT_RED;
  else if (liveData.soc <= 50.0f) socColor = 0xFD20;

  tft.setTextColor(liveData.valid ? socColor : TFT_DARKGREY, TFT_BLACK);
  String socStr = liveData.valid ? (String((int)round(liveData.soc)) + "%") : "--%";
  tft.drawString(socStr, 48, val1Y, 4);

  drawBatteryGraphic(94, showDebug ? 54 : 58, liveData.soc, liveData.current, liveData.valid, animStep);

  // 2. Voltage
  tft.fillRect(168, 52, 142, 48, TFT_BLACK);
  tft.setTextColor(liveData.valid ? TFT_CYAN : TFT_DARKGREY, TFT_BLACK);
  String vStr = liveData.valid ? (String(liveData.voltage, 2) + "V") : "--.--V";
  tft.drawString(vStr, 239, val1Y, 4);

  // 3. Current
  tft.fillRect(10, row2Y + 18, 142, 50, TFT_BLACK);
  uint16_t curColor = (liveData.current >= 0.0f) ? TFT_GREEN : 0xFD20;
  tft.setTextColor(liveData.valid ? curColor : TFT_DARKGREY, TFT_BLACK);
  String aStr = liveData.valid ? (String(liveData.current, 2) + "A") : "--.--A";
  tft.drawString(aStr, 81, val2Y, 4);

  // 4. Power & Time-To-Go
  tft.fillRect(168, row2Y + 18, 142, 50, TFT_BLACK);
  tft.setTextColor(liveData.valid ? TFT_WHITE : TFT_DARKGREY, TFT_BLACK);
  String pStr = liveData.valid ? (String((int)round(liveData.power)) + " W") : "--- W";
  tft.drawString(pStr, 239, pwrY, 4);

  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  String ttgStr = liveData.valid ? ("TTG: " + formatTTG(liveData.ttgMinutes)) : "TTG: --";
  tft.drawString(ttgStr, 239, ttgY, 2);

  // Optional Debug Strip (only drawn when showDebug == true)
  if (showDebug) {
    tft.fillRect(0, 188, 320, 17, 0x18E3);
    tft.setTextDatum(ML_DATUM);
    tft.setTextColor(TFT_YELLOW, 0x18E3);
    char* dbgLine = (char*)calloc(80, 1);
    snprintf(dbgLine, 80, "BLE:%lu VIC:%lu | %s", (unsigned long)dbgTotalBlePkts, (unsigned long)dbgVictronPkts, dbgLastMsg);
    tft.drawString(dbgLine, 4, 196, 1);
    free(dbgLine);
  }
}
void drawGraphPage() {
  tft.fillScreen(TFT_BLACK);
  drawTopBar("1-HR SOC TREND");
  drawNavButtons();

  // Graph plot box: X = 38..310 (272px wide), Y = 38..190 (152px tall)
  tft.drawRect(38, 38, 272, 152, 0x3186);

  // Y-Axis Labels (0% to 100% on the left)
  tft.setTextDatum(MR_DATUM);
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.drawString("100%", 35, 42, 1);
  tft.drawString("50%",  35, 114, 1);
  tft.drawString("0%",   35, 186, 1);

  // Subtle horizontal 50% reference line
  for (int gx = 40; gx < 308; gx += 6) {
    tft.drawPixel(gx, 114, 0x3186);
  }

  if (histCount < 2) {
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    tft.drawString("Collecting SOC samples (1/min)...", 174, 114, 2);
    return;
  }

  // Choose line colour based on latest SOC level
  float latestSoc = *(histSoc + histCount - 1);
  uint16_t lineColor = TFT_GREEN;
  if (latestSoc <= 20.0f) lineColor = TFT_RED;
  else if (latestSoc <= 50.0f) lineColor = 0xFD20;

  // Plot 0% to 100% SOC line across the 60-minute width
  for (int i = 1; i < histCount; i++) {
    int x0 = 40 + ((i - 1) * 268) / (HISTORY_LEN - 1);
    int x1 = 40 + (i * 268) / (HISTORY_LEN - 1);

    float raw0 = *(histSoc + i - 1);
    float raw1 = *(histSoc + i);
    float s0 = constrain(raw0, 0.0f, 100.0f);
    float s1 = constrain(raw1, 0.0f, 100.0f);

    int y0 = 188 - (int)((s0 / 100.0f) * 148.0f);
    int y1 = 188 - (int)((s1 / 100.0f) * 148.0f);

    tft.drawLine(x0, y0, x1, y1, lineColor);
    tft.drawLine(x0, y0 + 1, x1, y1 + 1, lineColor);
  }
}

void drawInfoPage() {
tft.fillScreen(TFT_BLACK);
drawTopBar("CONTROLS");
drawNavButtons();
tft.setTextDatum(TL_DATUM);
tft.setTextColor(TFT_WHITE, TFT_BLACK);
if (!isApMode && WiFi.status() == WL_CONNECTED) {
tft.drawString("Wi-Fi: " + WiFi.SSID(), 14, 36, 2);
tft.setTextColor(TFT_GREEN, TFT_BLACK);
tft.drawString("Web: http://" + WiFi.localIP().toString(), 14, 58, 2);
} else {
tft.drawString("AP: Victron-Monitor-Setup", 14, 36, 2);
tft.setTextColor(TFT_CYAN, TFT_BLACK);
tft.drawString("Web: 192.168.4", 14, 58, 2);
}
tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
tft.drawString("Consumed Ah: " + String(liveData.consumedAh, 1) + " Ah", 14, 82, 2);
// 1. Left Button: Toggle Debug Bar
uint16_t dbgBg = showDebug ? 0x04A0 : 0x2945;
tft.fillRoundRect(14, 114, 140, 50, 8, dbgBg);
tft.setTextDatum(MC_DATUM);
tft.setTextColor(TFT_WHITE, dbgBg);
tft.drawString(showDebug ? "DEBUG: ON" : "DEBUG: OFF", 84, 139, 2);
// 2. Right Button: Restart ESP32
tft.fillRoundRect(166, 114, 140, 50, 8, 0xA000);
tft.setTextColor(TFT_WHITE, 0xA000);
tft.drawString("RESTART ESP", 236, 139, 2);
}
void renderCurrentPage(bool fullRedraw) {
if (!screenOn) return;
if (currentPage == PAGE_MAIN) {
if (fullRedraw) drawMainPageFull();
updateMainValues();
} else if (currentPage == PAGE_GRAPH) {
drawGraphPage();
} else {
drawInfoPage();
}
}
void setScreenPower(bool turnOn) {
screenOn = turnOn;
if (screenOn) {
digitalWrite(TFT_BL_PIN, HIGH);
delay(20);
renderCurrentPage(true);
} else {
tft.fillScreen(TFT_BLACK);
digitalWrite(TFT_BL_PIN, LOW);
}
}
void triggerRestartWithSplash() {
digitalWrite(TFT_BL_PIN, HIGH);
tft.fillScreen(TFT_BLACK);
tft.setTextDatum(MC_DATUM);
tft.setTextColor(TFT_YELLOW, TFT_BLACK);
tft.drawString("Restarting Victron Monitor...", 160, 120, 2);
delay(800);
ESP.restart();
}
// ==========================================
// 7. WEB SERVER HANDLERS
// ==========================================
void handleRoot() {
  String socVal = liveData.valid ? String(liveData.soc, 1) : "--.-";
  String vVal   = liveData.valid ? String(liveData.voltage, 2) : "--.--";
  String aVal   = liveData.valid ? String(liveData.current, 2) : "--.--";
  String pVal   = liveData.valid ? String((int)round(liveData.power)) : "---";
  String ahVal  = liveData.valid ? String(liveData.consumedAh, 1) : "--.-";
  String ttgVal = liveData.valid ? formatTTG(liveData.ttgMinutes) : "--";
  String dbgBtnLabel = showDebug ? "Debug: ON" : "Debug: OFF";

  String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  page += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  page += "<meta http-equiv='refresh' content='5'>";
  page += "<title>Victron SmartShunt Monitor</title>";
  page += "<style>";
  page += "body{background:#0b0c10;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:16px;}";
  page += ".wrap{max-width:540px;margin:0 auto;}";
  page += ".hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:8px;flex-wrap:wrap;}";
  page += "h2{margin:0;color:#66fcf1;font-size:1.3rem;}";
  page += ".btns{display:flex;gap:8px;}";
  page += ".btn{background:#ff2a9d;color:#fff;text-decoration:none;padding:8px 12px;border-radius:8px;font-weight:700;font-size:0.85rem;border:none;cursor:pointer;}";
  page += ".btn-sec{background:#2a2f3d;}";
  page += ".btn-warn{background:#b81d13;}";
  page += ".grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}";
  page += ".card{background:#151821;border:1px solid #2a2f3d;border-radius:12px;padding:16px;}";
  page += ".lbl{font-size:0.78rem;color:#9aa3b2;text-transform:uppercase;letter-spacing:0.5px;}";
  page += ".val{font-size:1.9rem;font-weight:700;margin-top:6px;color:#fff;}";
  page += ".cyan{color:#66fcf1;}.green{color:#45f39a;}";
  page += ".dbg{background:#1f2833;border:1px solid #45a29e;color:#ffd166;padding:10px;border-radius:8px;font-size:0.82rem;margin-top:14px;font-family:monospace;}";
  page += "</style></head><body><div class='wrap'>";

  page += "<div class='hdr'><h2>Victron SmartShunt</h2><div class='btns'>";
  page += "<a class='btn btn-sec' href='/toggle_debug'>" + dbgBtnLabel + "</a>";
  page += "<a class='btn' href='/config'>Settings</a>";
  page += "<a class='btn btn-warn' href='/restart' onclick=\"return confirm('Restart Victron Monitor now?')\">Restart</a>";
  page += "</div></div>";

  page += "<div class='grid'>";
  page += "<div class='card'><div class='lbl'>State of Charge</div><div class='val green'>" + socVal + "%</div></div>";
  page += "<div class='card'><div class='lbl'>Battery Voltage</div><div class='val cyan'>" + vVal + " V</div></div>";
  page += "<div class='card'><div class='lbl'>Current</div><div class='val'>" + aVal + " A</div></div>";
  page += "<div class='card'><div class='lbl'>Power</div><div class='val'>" + pVal + " W</div></div>";
  page += "<div class='card'><div class='lbl'>Consumed Ah</div><div class='val'>" + ahVal + " Ah</div></div>";
  page += "<div class='card'><div class='lbl'>Time To Go</div><div class='val'>" + ttgVal + "</div></div>";
  page += "</div>";

  if (showDebug) {
    page += "<div class='dbg'>BLE Pkts: " + String(dbgTotalBlePkts) +
            " | Victron Pkts: " + String(dbgVictronPkts) +
            " | Status: " + htmlEscape(String(dbgLastMsg)) + "</div>";
  }

  page += "</div></body></html>";
  server.send(200, "text/html", page);
}

void handleToggleDebug() {
  showDebug = !showDebug;
  renderCurrentPage(true);
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleRestartWeb() {
  String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  page += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  page += "<meta http-equiv='refresh' content='6;url=/'>";
  page += "<style>body{background:#0b0c10;color:#fff;font-family:sans-serif;text-align:center;padding:40px;}h2{color:#ffd166;}</style>";
  page += "</head><body><h2>Restarting Victron Monitor...</h2><p>Returning to dashboard in 6 seconds...</p></body></html>";

  server.send(200, "text/html", page);
  delay(500);
  triggerRestartWithSplash();
}

void handleConfig() {
  String staStatus = (!isApMode && WiFi.status() == WL_CONNECTED)
    ? ("Connected (" + WiFi.localIP().toString() + ")")
    : "Setup Hotspot Mode (192.168.4.1)";

  String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  page += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  page += "<title>Victron Monitor Settings</title>";
  page += "<style>";
  page += "body{background:#0b0c10;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;display:flex;justify-content:center;}";
  page += ".card{background:#151821;border:1px solid #2a2f3d;border-radius:14px;padding:24px;max-width:480px;width:100%;}";
  page += "h2{margin-top:0;color:#ff2a9d;}";
  page += "label{display:block;margin:14px 0 6px;font-size:0.9rem;color:#ccc;}";
  page += "input{width:100%;padding:10px;border-radius:8px;border:1px solid #3a4152;background:#0b0c10;color:#fff;font-size:1rem;box-sizing:border-box;}";
  page += "button{width:100%;margin-top:20px;padding:12px;border:none;border-radius:8px;background:#ff2a9d;color:#fff;font-size:1rem;font-weight:700;cursor:pointer;}";
  page += ".info{background:#1f2833;padding:10px;border-radius:8px;font-size:0.85rem;margin-bottom:14px;color:#66fcf1;}";
  page += ".back{display:inline-block;margin-bottom:14px;color:#aaa;text-decoration:none;font-size:0.9rem;}";
  page += "</style></head><body><div class='card'>";

  page += "<a class='back' href='/'>&larr; Back to Live Dashboard</a>";
  page += "<h2>Monitor Settings</h2>";
  page += "<div class='info'>Network: " + staStatus + "</div>";
  page += "<form method='POST' action='/save'>";

  page += "<label>Victron Shunt Encryption Key (32 Hex Chars)</label>";
  page += "<input type='text' name='vkey' maxlength='32' placeholder='e.g. a1b2c3d4e5f6...' value='" + htmlEscape(victronKeyHex) + "' required>";

  page += "<label>Wi-Fi Network Name (SSID)</label>";
  page += "<input type='text' name='ssid' placeholder='Enter your Wi-Fi SSID' value='" + htmlEscape(wifiSSID) + "'>";

  page += "<label>Wi-Fi Network Password</label>";
  page += "<input type='password' name='wpass' placeholder='Enter your Wi-Fi password' value='" + htmlEscape(wifiPass) + "'>";

  page += "<label>Setup Hotspot Password (Min 8 chars)</label>";
  page += "<input type='text' name='appass' minlength='8' value='" + htmlEscape(apPassword) + "' required>";

  page += "<button type='submit'>Save &amp; Restart</button>";
  page += "</form></div></body></html>";

  server.send(200, "text/html", page);
}

void handleSave() {
  String newKey  = server.arg("vkey");
  String newSsid = server.arg("ssid");
  String newPass = server.arg("wpass");
  String newAp   = server.arg("appass");

  newKey.trim();
  newSsid.trim();
  newAp.trim();
  if (newAp.length() < 8) newAp = "Victron123";

  prefs.begin("victron_cfg", false);
  prefs.putString("vkey", newKey);
  prefs.putString("ssid", newSsid);
  prefs.putString("wpass", newPass);
  prefs.putString("appass", newAp);
  prefs.end();

  String page = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  page += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  page += "<meta http-equiv='refresh' content='6;url=/'>";
  page += "<style>body{background:#0b0c10;color:#fff;font-family:sans-serif;text-align:center;padding:40px;}h2{color:#45f39a;}</style>";
  page += "</head><body><h2>Settings Saved!</h2><p>Rebooting Victron Monitor now...</p></body></html>";

  server.send(200, "text/html", page);
  delay(500);
  triggerRestartWithSplash();
}

// ==========================================
// 8. SETUP & MAIN LOOP
// ==========================================
void setup() {
WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
Serial.begin(115200);
delay(100);
snprintf(dbgLastMsg, 64, "Scanning for Shunt...");
// 1. Isolate all SPI Chip-Select lines HIGH before touching display/touch
pinMode(TFT_CS_PIN, OUTPUT);
digitalWrite(TFT_CS_PIN, HIGH);
pinMode(XPT2046_CS, OUTPUT);
digitalWrite(XPT2046_CS, HIGH);
pinMode(SD_CS_PIN, OUTPUT);
digitalWrite(SD_CS_PIN, HIGH);
delay(50);
// 2. Initialize TFT Display & Backlight
tft.init();
tft.setRotation(1);
pinMode(TFT_BL_PIN, OUTPUT);
digitalWrite(TFT_BL_PIN, HIGH);
tft.fillScreen(TFT_BLACK);
// 3. Initialize Touch on VSPI
touchSPI.begin(XPT2046_CLK, XPT2046_MISO, XPT2046_MOSI, XPT2046_CS);
ts.begin(touchSPI);
ts.setRotation(1);
// 4. Load Saved Settings from NVS Flash
prefs.begin("victron_cfg", false);
victronKeyHex = prefs.getString("vkey", "");
apPassword    = prefs.getString("appass", "Victron123");
wifiSSID      = prefs.getString("ssid", "");
wifiPass      = prefs.getString("wpass", "");
prefs.end();
apPassword.trim();
if (apPassword.length() < 8) apPassword = "Victron123";
hasValidKey = hexToBytes(victronKeyHex, aesKey, 16);
// 5. Initialize NimBLE BEFORE Wi-Fi for clean DMA memory
NimBLEDevice::init("");
NimBLEScan* pScan = NimBLEDevice::getScan();
pScan->setScanCallbacks(new VictronScanCallbacks(), false);
pScan->setDuplicateFilter(false);
pScan->setActiveScan(true);
pScan->setInterval(100);
pScan->setWindow(60);
pScan->setMaxResults(0);
// 6. Single-Mode Wi-Fi Startup (STA if reachable, otherwise AP fallback)
tft.setTextDatum(MC_DATUM);
tft.setTextColor(TFT_WHITE, TFT_BLACK);
WiFi.persistent(false);
WiFi.setSleep(true); // Required for Wi-Fi + BLE coexistence
bool connectedToWifi = false;
if (wifiSSID.length() > 0) {
WiFi.mode(WIFI_STA);
WiFi.setTxPower(WIFI_POWER_11dBm);
tft.drawString("Connecting Wi-Fi: " + wifiSSID, 160, 110, 2);
WiFi.begin(wifiSSID.c_str(), wifiPass.c_str());
unsigned long startAttempt = millis();
while (WiFi.status() != WL_CONNECTED && millis() - startAttempt < 8000) {
delay(250);
}
if (WiFi.status() == WL_CONNECTED) {
connectedToWifi = true;
isApMode = false;
tft.fillScreen(TFT_BLACK);
tft.drawString("Wi-Fi Connected!", 160, 100, 2);
tft.drawString("http://" + WiFi.localIP().toString(), 160, 125, 2);
delay(2000);
}
}
if (!connectedToWifi) {
WiFi.disconnect(true);
delay(100);
WiFi.mode(WIFI_AP);
WiFi.setTxPower(WIFI_POWER_11dBm);
bool apStarted = WiFi.softAP("Victron-Monitor-Setup", apPassword.c_str());
isApMode = true;
tft.fillScreen(TFT_BLACK);
tft.drawString(apStarted ? "AP: Victron-Monitor-Setup" : "AP Failed!", 160, 85, 2);
tft.drawString("Pass: " + apPassword, 160, 110, 2);
tft.drawString("Open 192.168.4", 160, 135, 2);
delay(2000);
}
// 7. Start Web Server Routes
server.on("/", HTTP_GET, handleRoot);
server.on("/config", HTTP_GET, handleConfig);
server.on("/save", HTTP_POST, handleSave);
server.on("/toggle_debug", HTTP_GET, handleToggleDebug);
server.on("/restart", HTTP_GET, handleRestartWeb);
server.begin();
// 8. Draw Initial UI & Begin BLE Scan
renderCurrentPage(true);
pScan->start(0, false, true);
}
void loop() {
server.handleClient();
// Copy new BLE telemetry safely
bool updated = false;
if (newDataAvailable) {
portENTER_CRITICAL(&dataMux);
liveData = sharedData;
newDataAvailable = false;
portEXIT_CRITICAL(&dataMux);
updated = true;
}
// Record 1-minute SOC history point
if (liveData.valid && (millis() - lastHistSampleMs >= 60000 || histCount == 0)) {
lastHistSampleMs = millis();
if (histCount < HISTORY_LEN) {
*(histSoc + histCount) = liveData.soc;
histCount++;
} else {
for (int i = 1; i < HISTORY_LEN; i++) {
*(histSoc + i - 1) = *(histSoc + i);
}
*(histSoc + HISTORY_LEN - 1) = liveData.soc;
}
if (screenOn && currentPage == PAGE_GRAPH) renderCurrentPage(true);
}
// Handle Touchscreen Taps (works even when screen backlight is OFF!)
if (ts.tirqTouched() && ts.touched() && (millis() - lastTouchMs > 350)) {
TS_Point p = ts.getPoint();
lastTouchMs = millis();
int tx = map(p.x, 200, 3800, 0, 320);
int ty = map(p.y, 200, 3800, 0, 240);
// 1. Top-Left Screen Power Button (x <= 60, y <= 40)
if (tx <= 60 && ty <= 40) {
setScreenPower(!screenOn);
}
// 2. Ignore all other touches while screen is turned off
else if (screenOn) {
// Bottom Navigation Bar (Y >= 195)
if (ty >= 195) {
ScreenPage nextPage = currentPage;
if (tx < 107) nextPage = PAGE_MAIN;
else if (tx < 214) nextPage = PAGE_GRAPH;
else nextPage = PAGE_INFO;
if (nextPage != currentPage) {
currentPage = nextPage;
renderCurrentPage(true);
}
}
// Action Buttons on NETWORK Page (Y = 110..170)
else if (currentPage == PAGE_INFO && ty >= 110 && ty <= 170) {
if (tx >= 10 && tx <= 156) {
showDebug = !showDebug;
renderCurrentPage(true);
} else if (tx >= 164 && tx <= 310) {
triggerRestartWithSplash();
}
}
}
}
  // Animate charge/discharge arrows every 350ms when screen is awake on Main page
  if (screenOn && currentPage == PAGE_MAIN && liveData.valid && (millis() - lastAnimMs >= 350)) {
    lastAnimMs = millis();
    animStep = (animStep + 1) % 3;
    drawBatteryGraphic(94, showDebug ? 54 : 58, liveData.soc, liveData.current, liveData.valid, animStep);
  }
// Refresh live numbers on screen every 1 second while awake
if (screenOn && currentPage == PAGE_MAIN && (updated || millis() - lastUiRefreshMs >= 1000)) {
lastUiRefreshMs = millis();
updateMainValues();
}
delay(5);
}
