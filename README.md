# What’s-that-WiFi?

![What's-that-WiFi?](media/app_icon.png)

**What’s-that-WiFi?** is a simple desktop application for Windows that helps you assess the security of public Wi-Fi networks. It automatically scans the airwaves, analyzes key network parameters, and detects signs of **Evil Twin** attacks (fake access points).

## 📌 Key Features

*   **Security Analysis:** Evaluates networks based on encryption type, signal strength, hardware vendor, and other parameters.
*   **Evil Twin Detection:** Compares network names (SSID) and physical addresses (BSSID) to find fake access points.
*   **Simple Interface:** An intuitive GUI with color-coded security indicators (green/yellow/red).
*   **Background Operation:** The app runs in the system tray and automatically analyzes the network you connect to.
*   **Flexible Settings:** Choose a theme (Light, Dark, OLED) and disable Evil Twin checks (not recommended).

## 🚀 Installation and Launch

1.  Make sure you have **Python 3.8+** installed.
2.  Clone or download this repository.
3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4.  Run the application:
    ```bash
    python main.py
    ```

## ⚙️ Requirements

*   Operating System: **Windows** (as it uses the `netsh` command).
*   Python 3.8+

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.