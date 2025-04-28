import sys
import subprocess
import requests
import time
from PyQt5.QtWidgets import QApplication,QHBoxLayout, QMainWindow, QListWidget, QLabel, QVBoxLayout, QWidget, QPushButton, QTextEdit, QAction, QMenu, QMessageBox, QSystemTrayIcon
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QTimer
from plyer import notification

sec_bal = {
    'encryption': {
        'open': -50,
        'WEP': -40,
        'WPA_TKIP': -20,
        'WPA2_AES': 20,
        'WPA3': 40
    },
    'evil_twin': {
        'different_vendor': -40,
        'different_uptime': -25,
        'similar_bssid': 5
    },
    'vendor': {
        'mixed': -30,
        'unknown': -20,
        'known': 5
    },
    'signal_strength': {
        'weak': -10,
        'moderate': 5,
        'strong': 10
    },
    'channel_width': {
        '20 MHz': 0,
        '40 MHz': 5,
        '80 MHz': 10,
        '160 MHz': 15
    },
    'wifi_standard': {
        '802.11b': -10,
        '802.11g': -10,
        '802.11n': 5,
        '802.11ac': 10,
        '802.11ax': 15
    },
    'frequency_band': {
        '2.4 GHz': 0,
        '5 GHz': 5
    }
}

class WiFiAnalyzer:
    def __init__(self):
        self.current_network = None
        self.networks = []

    def scan_networks(self):
        try:
            res = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            out = res.stdout.decode('utf-8')
            networks = self.parse_netsh_output(out)
            self.networks = networks
        except Exception as e:
            notification.notify(
            title="What’s-that-WiFi?",
            message=(f'Ошибка при сканировании сетей: {e}'),)
            self.networks = []

    def analyze_network(self, network):
        details = {}
        bal = 0
        encryption = network.get("encryption", "open")
        if "WPA3" in encryption:
            encryption_key = "WPA3"
        elif "WPA2_AES" in encryption:
            encryption_key = "WPA2_AES"
        elif "WEP" in encryption:
            encryption_key = "WEP"
        elif "WPA" in encryption:
            encryption_key = "WPA_TKIP"
        else:
            encryption_key = "open"
    
        bal += sec_bal['encryption'].get(encryption_key, 0)
        details['encryption'] = f"Encryption type: {encryption} ({sec_bal['encryption'][encryption_key]} points)"
    
        signal = network.get("signal", 0)   
        signal_score = self.analyze_signal_strength(signal)
        bal += signal_score
        details['signal'] = f"Signal strength: {signal}% ({signal_score} points)"
    
        channel_width = network.get("channel_width", "20 MHz")
        channel_width_score = self.analyze_channel_width(channel_width)
        bal += channel_width_score
        details['channel_width'] = f"Channel width: {channel_width} ({channel_width_score} points)"
    
        standard = network.get("wifi_standard", "802.11n")
        standard_score = self.analyze_wifi_standard(standard)
        bal += standard_score
        details['wifi_standard'] = f"WiFi Standard: {standard} ({standard_score} points)"
    
        frequency = network.get("frequency", "2.4 GHz")
        frequency_score = self.analyze_frequency_band(frequency)
        bal += frequency_score
        details['frequency_band'] = f"Frequency band: {frequency} ({frequency_score} points)"

        bssid = network.get("bssid")
        
        if self.check_evil_twin(network.get("ssid")):
            bal += sec_bal['evil_twin']['different_vendor']
            details['evil_twin'] = "Evil Twin attack detected! (-40 points)"
        else:
            details['evil_twin'] = "No Evil Twin attack detected (0 points)"
    
        vendor_score = self.check_vendor(bssid)
        bal += sec_bal['vendor'].get(vendor_score, 0)
        details['vendor'] = f"Vendor: {vendor_score} ({sec_bal['vendor'][vendor_score]} points)"

        connected_devices = network.get("connected_devices", 0)
        if connected_devices > 10:
            bal -= 5
            details["connected_devices"] = f"Number of connections: {connected_devices} (-5 points)"
        elif (connected_devices <= 5) and (connected_devices >= 0):
            bal += 5
            details["connected_devices"] = f"Number of connections: {connected_devices} (+5 points)"
        elif connected_devices == -1:
            details["connected_devices"] = f"Number of connections not detected (0 points)"

        details['total_score'] = f"Total score: {bal}"
        return bal, details

    def check_evil_twin(self, ssid):
        duplicates = [n for n in self.networks if n.get("ssid") == ssid]
        if len(duplicates) > 1:
            vendors = set(self.check_vendor(n.get("bssid")) for n in duplicates)
            if len(vendors) > 1:
                return True
        return False

    def check_vendor(self, bssid):
        if not self.is_valid_bssid(bssid):
            return 'unknown'
        url = f"https://api.macvendors.com/{bssid}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and response.text.strip():
                return 'known'
        except Exception as e:
            notification.notify(
            title="What’s-that-WiFi?",
            message=(f"Error checking vendor for {bssid}: {e}"),    
            timeout=10
            )

        return 'unknown'

    def is_valid_bssid(self, bssid):
        if not bssid:
            return False
        parts = bssid.split(":")
        if len(parts) != 6:
            return False
        for part in parts:
            if not part.isalnum() or len(part) != 2:
                return False
        return True

    def analyze_signal_strength(self, signal):
        if signal >= 80:
            return sec_bal['signal_strength']['strong']
        elif signal >= 50:
            return sec_bal['signal_strength']['moderate']
        else:
            return sec_bal['signal_strength']['weak']

    def analyze_channel_width(self, channel_width):
        return sec_bal['channel_width'].get(channel_width, 0)

    def analyze_wifi_standard(self, standard):
        return sec_bal['wifi_standard'].get(standard, 0)

    def analyze_frequency_band(self, frequency):
        return sec_bal['frequency_band'].get(frequency, 0)

    def parse_netsh_output(self, out):
        networks = []
        lines = out.split('\n')
        current_network = {}
        has_connected_devices = False

        for line in lines:
            line = line.strip()
            if line.startswith("SSID"):
                if current_network:
                    if not has_connected_devices:
                        current_network["connected_devices"] = -1
                    networks.append(current_network)
                current_network = {"ssid": line.split(":")[1].strip()}
                has_connected_devices = False
            elif line.startswith("BSSID"):
                current_network["bssid"] = line.split(":")[1].strip()
            elif "Шифрование" in line:
                encryption = line.split(":")[1].strip()
                if encryption == "CCMP":
                    current_network["encryption"] = "WPA2_AES"
                else:
                    current_network["encryption"] = encryption or "open"
            elif "Сигнал" in line:
                try:
                    signal = int(line.split(":")[1].strip().replace("%", ""))
                    current_network["signal"] = signal
                except ValueError:
                    current_network["signal"] = 0
            elif "Подключенные станции" in line:
                has_connected_devices = True
                try:
                    connected_devices = int(line.split(":")[1].strip())
                    current_network["connected_devices"] = connected_devices
                except ValueError:
                    current_network["connected_devices"] = -1 

        if current_network:
            if not has_connected_devices:
                current_network["connected_devices"] = -1
            networks.append(current_network)
    
        return networks

class WiFiApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.analyzer = WiFiAnalyzer()
        self.initUI()
        self.create_tray_icon()
        self.previous_ssid = None
        self.start_background_monitoring()
        self.setWindowIcon(QIcon("icon.png"))

    def initUI(self):
        self.setWindowTitle('What’s-that-WiFi?')
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        main_layout = QHBoxLayout()
        self.network_list = QListWidget()
        self.network_list.itemClicked.connect(self.show_network_details)
        main_layout.addWidget(self.network_list, stretch=1)

        right_column_layout = QVBoxLayout()

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        right_column_layout.addWidget(self.details_text, stretch=4)

        button_layout = QHBoxLayout()
        self.scan_button = QPushButton('Scan nearby networks')
        self.scan_button.setMinimumHeight(50)
        self.scan_button.clicked.connect(self.update_networks)
        button_layout.addWidget(self.scan_button, stretch=8)

        self.exit_button = QPushButton('Exit')
        self.exit_button.setFixedSize(100, 50)
        self.exit_button.clicked.connect(self.close_application)
        button_layout.addWidget(self.exit_button, stretch=2)

        right_column_layout.addLayout(button_layout, stretch=1)

        main_layout.addLayout(right_column_layout, stretch=1)

        self.central_widget.setLayout(main_layout)

    def create_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            notification.notify(
            title="What’s-that-WiFi?",
            message=('System tray is not available on this system.'),
            )

            return

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("icon.png"))

        menu = QMenu()
        restore_action = QAction("Open", self)
        restore_action.triggered.connect(self.show)
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.close_application)

        menu.addAction(restore_action)
        menu.addAction(quit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.show()

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "What’s-that-WiFi?",
            "The application has been minimized to the tray",
            QSystemTrayIcon.Information,
            2000
        )

    def close_application(self):
        reply = QMessageBox.question(
            self,
            'Exit',
            'Are you sure you want to exit?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            QApplication.quit()

    def update_networks(self):
        self.analyzer.scan_networks()
        self.network_list.clear()
        for network in self.analyzer.networks:
            bal, _ = self.analyzer.analyze_network(network)
            item = f"{network.get('ssid')} - Score: {bal}"
            self.network_list.addItem(item)

    def show_network_details(self, item):
        ssid = item.text().split(" - ")[0]
        network = next((n for n in self.analyzer.networks if n.get("ssid") == ssid), None)
        if network:
            _, details = self.analyzer.analyze_network(network)
            details_text = "\n".join(details.values())
            self.details_text.setText(details_text)

    def start_background_monitoring(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_current_connection)
        self.timer.start(10000)

    def check_current_connection(self):
        try:
            self.analyzer.scan_networks()

            res = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            out = res.stdout.decode('utf-8')
            ssid = None

            for line in out.split('\n'):
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":")[1].strip()
                    break

            if ssid and ssid != self.previous_ssid:
                self.previous_ssid = ssid
                network = next((n for n in self.analyzer.networks if n.get("ssid") == ssid), None)
                if network:
                    bal, _ = self.analyzer.analyze_network(network)
                    self.send_notification(ssid, bal)
        except Exception as e:
            notification.notify(
            title="What’s-that-WiFi?",
            message=(f"Ошибка при проверке текущего подключения: {e}")
        )


    def send_notification(self, ssid, bal):
        if bal <= 10:
            message = f"Network '{ssid}' is critically unsafe! Score: {bal}"
        if (bal > -10) and (bal <= 0):
            message = f"Network '{ssid}' is unsafe. Score: {bal}"
        if (bal > 0) and (bal <= 10):
            message = f"Network '{ssid}' is relatively safe. Score: {bal}"
        if (bal > 10) and (bal <= 20):
            message = f"Network '{ssid}' is safe. Score: {bal}"
        if bal > 20:
            message = f"Network '{ssid}' is absolutely safe. Score: {bal}"
        notification.notify(
            title="What’s-that-WiFi?",
            message=message,
            timeout=10
        )

if __name__ == '__main__':
    app = QApplication([])
    app.setStyleSheet("""
        QWidget {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QPushButton {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px;
        }
        QPushButton:hover {
            background-color: #45a049;
        }
    """)
    ex = WiFiApp()
    ex.show()
    sys.exit(app.exec_())
