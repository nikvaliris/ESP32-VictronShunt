# ESP32 Victron SmartShunt Monitor (CYD)

A standalone, touchscreen battery monitor and Wi-Fi web dashboard for the **Victron SmartShunt** (and BMV battery monitors) built for the **ESP32-2432S028R ("Cheap Yellow Display" / CYD)**.

It passively listens to Victron Instant Readout BLE advertisements, decrypts the AES-128-CTR payload locally on the ESP32, and displays real-time battery telemetry on both the 2.8" TFT touchscreen and a responsive dark-mode web interface.

---

## ✨ Features

* **Passive Victron BLE Decryption:** Reads encrypted Instant Readout manufacturer advertisements (`0x02E1`) directly over Bluetooth Low Energy using `NimBLE` and `mbedTLS` (AES-128-CTR)—no Victron VE.Direct cable required.
* **Live Touchscreen Dashboard (`LIVE`):**
  * Displays **State of Charge (%)**, **Battery Voltage (V)**, **Current (A)**, **Power (W)**, and **Time-To-Go (TTG)**.
  * **Dynamic Battery Graphic:** Colour-coded fill bar (**Green** > 50%, **Amber** 21–50%, **Red** ≤ 20%).
  * **Animated Flow Indicators:** 3-step animated chevrons showing current flowing **into** the battery while charging and **out of** the battery while discharging.
* **1-Hour Rolling SOC Trend (`HISTORY`):** Plots a 60-minute State of Charge line graph scaled from **0% to 100%** (1 sample per minute).
* **Night-Mode Screen Power Toggle (`OFF`):** Tap the top-left **OFF** button to turn off the TFT backlight while keeping BLE scanning, history logging, and the web server running in the background. Tap the same top-left corner anytime to wake the screen.
* **Built-In Web Server & Configuration Portal:**
  * Dark-mode live web dashboard (auto-refreshes every 5 seconds).
  * Browser-based settings page (`/config`) to store your **32-character Victron AES Encryption Key**, **Wi-Fi credentials**, and **Setup Hotspot password** in non-volatile flash (`Preferences`).
  * Automatic fallback to `Victron-Monitor-Setup` Wi-Fi Access Point (`192.168.4.1`) if home/vehicle Wi-Fi is unavailable.
  * Toggleable on-screen and web BLE packet debug bar plus remote reboot controls.

---

## 🛠 Hardware Requirements

* **Board:** ESP32-2432S028R (2.8" 320×240 ILI9341 TFT + XPT2046 Resistive Touch "Cheap Yellow Display")
* **Sensor:** Victron SmartShunt or BMV-712 with **Instant Readout** enabled in the VictronConnect app

### Pinout Reference (`ESP32-2432S028R`)

| Function | GPIO Pin | Notes |
| :--- | :---: | :--- |
| TFT Backlight (`TFT_BL`) | `21` | Controlled for screen OFF / touch-to-wake |
| TFT Chip Select (`TFT_CS`) | `15` | HSPI |
| SD Card CS (`SD_CS`) | `5` | Held `HIGH` at boot to isolate SPI bus |
| Touch IRQ (`XPT2046_IRQ`) | `36` | VSPI |
| Touch MOSI (`XPT2046_MOSI`) | `32` | VSPI |
| Touch MISO (`XPT2046_MISO`) | `39` | VSPI |
| Touch CLK (`XPT2046_CLK`) | `25` | VSPI |
| Touch CS (`XPT2046_CS`) | `33` | VSPI |

---

## 📦 Software & Library Dependencies

Install the following via the **Arduino IDE Library Manager**:

1. **ESP32 Board Package** (`esp32` by Espressif Systems, v2.0.16+)
2. **TFT_eSPI** by Bodmer *(configured for the ILI9341 240×320 CYD pinout)*
3. **XPT2046_Touchscreen** by Paul Stoffregen
4. **NimBLE-Arduino** by h2zero

*(Built-in ESP32 core libraries used: `WiFi`, `WebServer`, `Preferences`, `SPI`, `mbedtls/aes.h`)*

---

## 🔑 Getting Your Victron Encryption Key

1. Open the **VictronConnect** app on your phone and connect to your SmartShunt.
2. Tap the **Settings (gear icon)** → **Product Info**.
3. Enable **Instant Readout via Bluetooth** if it is not already turned on.
4. Tap **Instant Readout Details** (or **Show** next to Encryption Key) and copy the **32-character hexadecimal key**.

---

## 🚀 Setup & First Boot

1. Flash the sketch to your **ESP32-2432S028R** using the Arduino IDE (`ESP32 Dev Module`, Partition Scheme: `Default 4MB with spiffs` or `Huge APP`).
2. On first boot (before Wi-Fi is configured), the display will show:
   * **Wi-Fi Hotspot:** `Victron-Monitor-Setup`
   * **Default Password:** `Victron123`
3. Connect your phone or laptop to `Victron-Monitor-Setup` and browse to:
   ```text
   http://192.168.4
   ```
4. Enter your **32-character Victron Encryption Key**, your local **Wi-Fi SSID & Password** (optional), and a custom hotspot password, then click **Save & Restart**.
5. Once connected to your Wi-Fi network, the IP address is displayed on the **NETWORK** tab of the touchscreen.

---

## 📱 Touchscreen Navigation

* **Top-Left `OFF` Button:** Turns the screen backlight off/on. When the screen is off, tap the top-left corner (`x ≤ 60, y ≤ 40`) to wake it back up.
* **`LIVE` Tab:** Main 4-card telemetry view with animated battery flow graphic.
* **`HISTORY` Tab:** 1-hour rolling State of Charge (0–100%) trend graph.
* **`NETWORK` Tab:** Displays current Wi-Fi/AP IP address, Consumed Ah, **DEBUG: ON/OFF** toggle, and **RESTART ESP** button.

---

## 📄 Licence

This project is open-source and available under the [MIT Licence](LICENSE).
