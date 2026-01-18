import sys
import subprocess
import requests
import time
from fuzzywuzzy import fuzz
from PyQt5.QtWidgets import (QApplication, QHBoxLayout, QMainWindow, QListWidget, QListWidgetItem,
                             QLabel, QStyle, QVBoxLayout, QWidget, QPushButton, QTextEdit, QAction, QMenu,
                             QMessageBox, QSystemTrayIcon, QStackedWidget, QComboBox, QFormLayout, QScrollArea, QStyledItemDelegate, QCheckBox)
from PyQt5.QtGui import QIcon, QColor, QPalette, QPixmap, QPen
from PyQt5.QtCore import QTimer, Qt, QSize
from plyer import notification
import configparser
import os

CONFIG_FILE = 'data/settings.cfg'

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

accent_color = config.get('UI', 'accent_color', fallback='#842395')
theme = config.get('UI', 'theme', fallback='light')
evil_twin_enabled = config.getboolean('Security', 'evil_twin_enabled', fallback=True)

COLOR_MAP = {
    'Green': "#28722A",
    'Purple': "#842395",
    'White': '#FFFFFF',
    'Blue': "#175C95",
    'Yellow': "#B6A82B",
    'Red': "#BA372D"
}

THEME_MAP = {
    'Light': 'light',
    'Dark': 'dark',
    'OLED (Black)': 'oled'
}

sec_bal = {
    'encryption': {
        'open': -50,
        'WEP': -40,
        'WPA_TKIP': -20,
        'WPA2_AES': 20,
        'WPA3': 40
    },
    'evil_twin': {
        'bssid_mismatch_both_checks': -35
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
        self.ssid_pos_match_threshold = 40
        self.ssid_fuzz_threshold = 90
        self.bssid_pos_match_threshold = 50

    def scan_networks(self):
        try:
            res = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            out = res.stdout.decode('utf-8')
            networks = self.parse_netsh_output(out)
            self.networks = networks
        except Exception as e:
            notification.notify(
                title="What’s-that-WiFi?",
                message=(f'Error scanning networks: {e}'),
            )
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
        details['wifi_standard'] = f"Wi-Fi standard: {standard} ({standard_score} points)"

        frequency = network.get("frequency", "2.4 GHz")
        frequency_score = self.analyze_frequency_band(frequency)
        bal += frequency_score
        details['frequency_band'] = f"Frequency band: {frequency} ({frequency_score} points)"

        bssid = network.get("bssid")
        ssid = network.get("ssid")

        evil_twin_result = self.check_evil_twin(ssid, bssid)
        if evil_twin_result['is_evil_twin']:
             bal += sec_bal['evil_twin']['bssid_mismatch_both_checks']
             details['evil_twin'] = f"Evil Twin attack detected (BSSID mismatch)! ({sec_bal['evil_twin']['bssid_mismatch_both_checks']} points)"
             details['evil_twin'] += f" Linked to: SSID '{evil_twin_result['matched_ssid']}', BSSID '{evil_twin_result['matched_bssid']}'"
        else:
            details['evil_twin'] = "No Evil Twin attack detected (0 points)"

        vendor_score = self.check_vendor(bssid)
        if vendor_score is None:
            vendor_score = 'unknown'
        bal += sec_bal['vendor'].get(vendor_score, 0)
        details['vendor'] = f"Vendor: {vendor_score} ({sec_bal['vendor'][vendor_score]} points)"

        connected_devices = network.get("connected_devices", 0)
        if connected_devices > 10:
            bal -= 5
            details["connected_devices"] = f"Connected devices: {connected_devices} (-5 points)"
        elif (connected_devices <= 5) and (connected_devices >= 0):
            bal += 5
            details["connected_devices"] = f"Connected devices: {connected_devices} (+5 points)"
        elif connected_devices == -1:
            details["connected_devices"] = f"Connected devices not determined (0 points)"

        details['total_score'] = f"Total score: {bal}"
        return bal, details

    def check_evil_twin(self, current_ssid, current_bssid):
        global evil_twin_enabled
        if not evil_twin_enabled:
            return {'is_evil_twin': False, 'matched_ssid': None, 'matched_bssid': None}

        for net in self.networks:
            other_ssid = net.get("ssid")
            other_bssid = net.get("bssid")
            if other_ssid == current_ssid and other_bssid == current_bssid:
                continue

            min_len_ssid = min(len(current_ssid), len(other_ssid))
            if min_len_ssid > 0:
                pos_match_ssid = sum(c1 == c2 for c1, c2 in zip(current_ssid, other_ssid)) / min_len_ssid * 100
            else:
                pos_match_ssid = 100 if current_ssid == other_ssid else 0

            fuzz_match_ssid = fuzz.ratio(current_ssid, other_ssid)

            ssid_is_similar = (pos_match_ssid >= self.ssid_pos_match_threshold) or (fuzz_match_ssid >= self.ssid_fuzz_threshold)

            if ssid_is_similar:
                min_len_bssid = min(len(current_bssid), len(other_bssid))
                if min_len_bssid > 0:
                    pos_match_bssid = sum(c1 == c2 for c1, c2 in zip(current_bssid, other_bssid)) / min_len_bssid * 100
                else:
                    pos_match_bssid = 100 if current_bssid == other_bssid else 0

                bssid_is_similar = pos_match_bssid >= self.bssid_pos_match_threshold

                if not bssid_is_similar:
                     return {'is_evil_twin': True, 'matched_ssid': other_ssid, 'matched_bssid': other_bssid}

        return {'is_evil_twin': False, 'matched_ssid': None, 'matched_bssid': None}

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
                current_network["bssid"] = line.split(":", 1)[1].strip().split()[0]
            elif "Authentication" in line or "Шифрование" in line:
                encryption = line.split(":")[1].strip()
                if encryption == "CCMP":
                    current_network["encryption"] = "WPA2_AES"
                else:
                    current_network["encryption"] = encryption or "open"
            elif "Signal" in line or "Сигнал" in line:
                try:
                    signal = int(line.split(":")[1].strip().replace("%", ""))
                    current_network["signal"] = signal
                except ValueError:
                    current_network["signal"] = 0
            elif "Number of clients" in line or "Подключенные станции" in line:
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

class ScoreDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        text = index.data()
        try:
            score = int(text.split(" - ")[1])
        except (IndexError, ValueError):
            score = 0

        if score < -10:
            score_color = QColor("#F44336")
        elif score <= 10:
            score_color = QColor("#FFEB3B")
        else:
            score_color = QColor("#4CAF50")

        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, option.palette.highlight())
        
        ssid_part = text.split(" - ")[0]
        score_part = str(score)

        painter.save()
        painter.setPen(option.palette.color(QPalette.Text))
        painter.drawText(option.rect.adjusted(10, 0, -10, 0), Qt.AlignVCenter | Qt.AlignLeft, ssid_part)
        painter.setPen(QPen(score_color))
        painter.drawText(option.rect.adjusted(10, 0, -10, 0), Qt.AlignVCenter | Qt.AlignRight, score_part)
        painter.restore()

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        size.setHeight(30)
        return size

class NetworksWidget(QWidget):
    def __init__(self, analyzer, app_instance):
        super().__init__()
        self.analyzer = analyzer
        self.app_instance = app_instance
        self.initUI()

    def initUI(self):
        main_layout = QHBoxLayout()
        self.network_list = QListWidget()
        self.network_list.setItemDelegate(ScoreDelegate())
        self.network_list.itemClicked.connect(self.show_network_details)
        main_layout.addWidget(self.network_list, stretch=1)

        right_column_layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setHtml("<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>Click a network to view details</div>")
        right_column_layout.addWidget(self.details_text, stretch=4)

        button_layout = QHBoxLayout()
        self.scan_button = QPushButton('Scan Nearby Networks')
        self.scan_button.setMinimumHeight(50)
        self.scan_button.clicked.connect(self.update_networks)
        button_layout.addWidget(self.scan_button, stretch=8)

        right_column_layout.addLayout(button_layout, stretch=1)
        main_layout.addLayout(right_column_layout, stretch=1)
        self.setLayout(main_layout)

    def update_networks(self):
        self.details_text.setHtml("<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>Scanning...</div>")

        self.analyzer.scan_networks()

        self.network_list.clear()
        for network in self.analyzer.networks:
            bal, _ = self.analyzer.analyze_network(network)
            ssid = network.get('ssid', 'Unknown')
            item_text = f"{ssid} - {bal}"
            self.network_list.addItem(item_text)

        self.details_text.setHtml("<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>Click a network to view details</div>")

    def show_network_details(self, item):
        full_text = item.text()
        ssid = full_text.split(" - ")[0]

        network = next((n for n in self.analyzer.networks if n.get("ssid") == ssid), None)
        if network:
            _, details = self.analyzer.analyze_network(network)
            details_text_content = "\n".join(details.values())
            self.details_text.setText(details_text_content)

    def close_application(self):
        self.app_instance.close_application()

class SettingsWidget(QWidget):
    def __init__(self, app_instance):
        super().__init__()
        self.app_instance = app_instance
        self.initUI()

    def initUI(self):
        layout = QFormLayout()

        self.accent_color_combo = QComboBox()
        self.accent_color_combo.addItems(list(COLOR_MAP.keys()))
        current_color_name = next((name for name, color in COLOR_MAP.items() if color == accent_color), 'Green')
        self.accent_color_combo.setCurrentText(current_color_name)
        self.accent_color_combo.currentTextChanged.connect(self.on_accent_color_changed)
        layout.addRow("Accent color:", self.accent_color_combo)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(list(THEME_MAP.keys()))
        current_theme_name = next((name for name, val in THEME_MAP.items() if val == theme), 'Dark')
        self.theme_combo.setCurrentText(current_theme_name)
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        layout.addRow("Theme:", self.theme_combo)

        self.evil_twin_checkbox = QCheckBox("Enable Evil Twin detection (recommended)")
        self.evil_twin_checkbox.setChecked(evil_twin_enabled)
        self.evil_twin_checkbox.stateChanged.connect(self.on_evil_twin_toggled)
        layout.addRow("Security check:", self.evil_twin_checkbox)

        warning_label = QLabel("⚠️ Disabling Evil Twin detection makes you vulnerable to Wi-Fi spoofing attacks!")
        warning_label.setStyleSheet("color: #F44336; font-weight: bold;")
        warning_label.setWordWrap(True)
        layout.addRow("", warning_label)

        self.setLayout(layout)

    def on_accent_color_changed(self, color_name):
        global accent_color
        new_color = COLOR_MAP.get(color_name, '#4CAF50')
        accent_color = new_color
        self.app_instance.apply_accent_color(accent_color)

    def on_theme_changed(self, theme_name):
        global theme
        new_theme = THEME_MAP.get(theme_name, 'dark')
        theme = new_theme
        self.app_instance.apply_accent_color(accent_color)

    def on_evil_twin_toggled(self, state):
        global evil_twin_enabled
        evil_twin_enabled = (state == Qt.Checked)
        self.app_instance.save_settings_to_config()

class AboutWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop)

        title_label = QLabel("What's-that-WiFi?")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        icon_label = QLabel()
        icon_path = "data/icon.png"
        if os.path.exists(icon_path):
            pixmap = QPixmap(icon_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                icon_label.setPixmap(scaled_pixmap)
            else:
                icon_label.setText("App Icon")
        else:
            icon_label.setText("App Icon")
        icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_label)

        info_text = QTextEdit()
        info_text.setHtml("""
        <h2>About the application</h2>
        <p><b>Version:</b> 0.2.1 EN Edition</p>
        <p><b>Developer:</b> bbblush</p>
        <p>Application for analyzing Wi-Fi network security.</p>
        """)
        info_text.setReadOnly(True)
        info_text.setMaximumHeight(200)
        layout.addWidget(info_text)

        self.setLayout(layout)

class WiFiApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.analyzer = WiFiAnalyzer()
        self.initUI()
        self.create_tray_icon()
        self.previous_ssid = None
        self.start_background_monitoring()
        self.setWindowIcon(QIcon("data/icon.png"))
        self.apply_accent_color(accent_color)

    def initUI(self):
        self.setWindowTitle('What’s-that-WiFi?')
        self.setGeometry(100, 100, 1000, 700)

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        self.networks_widget = NetworksWidget(self.analyzer, self)
        self.settings_widget = SettingsWidget(self)
        self.about_widget = AboutWidget()

        self.stacked_widget.addWidget(self.networks_widget)
        self.stacked_widget.addWidget(self.settings_widget)
        self.stacked_widget.addWidget(self.about_widget)

        self.sidebar = QListWidget()
        self.sidebar.setMaximumWidth(150)
        self.sidebar.setSpacing(5)
        self.sidebar.setIconSize(QSize(24, 24))

        about_item = QListWidgetItem(QIcon("data/icon.png"), "About")
        about_item.setToolTip("About")
        self.sidebar.addItem(about_item)

        separator1 = QListWidgetItem()
        separator1.setFlags(Qt.NoItemFlags)
        separator1.setText("---------------")
        self.sidebar.addItem(separator1)

        networks_item = QListWidgetItem(QIcon("data/wifi_icon.png"), "Networks")
        networks_item.setToolTip("Networks")
        self.sidebar.addItem(networks_item)

        settings_item = QListWidgetItem(QIcon("data/settings_icon.png"), "Settings")
        settings_item.setToolTip("Settings")
        self.sidebar.addItem(settings_item)

        separator2 = QListWidgetItem()
        separator2.setFlags(Qt.NoItemFlags)
        separator2.setText("---------------")
        self.sidebar.addItem(separator2)

        exit_item = QListWidgetItem(QIcon("data/exit_icon.png"), "Exit")
        exit_item.setToolTip("Exit")
        self.sidebar.addItem(exit_item)

        self.sidebar.currentRowChanged.connect(self.on_sidebar_item_clicked)

        main_layout = QHBoxLayout()
        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.stacked_widget)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.sidebar.setCurrentRow(2)

    def on_sidebar_item_clicked(self, index):
        if index == 0:
            self.stacked_widget.setCurrentIndex(2)
        elif index == 2:
            self.stacked_widget.setCurrentIndex(0)
        elif index == 3:
            self.stacked_widget.setCurrentIndex(1)
        elif index == 5:
            self.ask_exit_or_minimize()

    def ask_exit_or_minimize(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Exit")
        msg_box.setText("Do you want to exit the application or minimize it to the tray?")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)

        yes_button = msg_box.button(QMessageBox.Yes)
        if yes_button:
            yes_button.setText("Exit")
        no_button = msg_box.button(QMessageBox.No)
        if no_button:
            no_button.setText("Minimize to Tray")
        cancel_button = msg_box.button(QMessageBox.Cancel)
        if cancel_button:
            cancel_button.setText("Cancel")

        result = msg_box.exec_()

        if result == QMessageBox.Yes:
            QApplication.quit()
        elif result == QMessageBox.No:
            self.hide()
            self.tray_icon.showMessage(
                "What’s-that-WiFi?",
                "The application has been minimized to the tray",
                QSystemTrayIcon.Information,
                2000
            )

    def create_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            notification.notify(
                title="What’s-that-WiFi?",
                message=('System tray is not available on this system.'),
            )
            return
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("data/icon.png"))
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
        self.ask_exit_or_minimize()
        event.ignore()

    def close_application(self):
        QApplication.quit()

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
                message=(f"Error checking current connection: {e}")
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

    def apply_accent_color(self, color_hex):
        global accent_color
        accent_color = color_hex
        current_theme = theme

        if current_theme == 'light':
            bg_color = "#ffffff"
            text_color = "#000000"
            list_bg = "#f0f0f0"
            border_color = "#cccccc"
        elif current_theme == 'oled':
            bg_color = "#000000"
            text_color = "#ffffff"
            list_bg = "#111111"
            border_color = "#333333"
        else:
            bg_color = "#2b2b2b"
            text_color = "#ffffff"
            list_bg = "#3c3c3c"
            border_color = "#555555"

        app_style = f"""
        QWidget {{
            background-color: {bg_color};
            color: {text_color};
        }}
        QPushButton {{
            background-color: {color_hex};
            color: white;
            border: none;
            padding: 10px;
        }}
        QPushButton:hover {{
            background-color: {self.darken_color(color_hex, 0.1)};
        }}
        QComboBox {{
            background-color: {list_bg};
            color: {text_color};
            border: 1px solid {border_color};
            padding: 5px;
        }}
        QComboBox QAbstractItemView {{
            background-color: {list_bg};
            color: {text_color};
            selection-background-color: {color_hex};
        }}
        QListWidget {{
            background-color: {list_bg};
            color: {text_color};
            border: 1px solid {border_color};
            outline: none;
        }}
        QListWidget::item {{
            padding: 5px;
            margin: 0px;
            border: none;
        }}
        QListWidget::item:selected {{
            background-color: {color_hex};
        }}
        QListWidget::item:!enabled {{
            color: #888888;
        }}
        """
        QApplication.instance().setStyleSheet(app_style)
        self.save_settings_to_config()

    def darken_color(self, hex_color, factor):
        color = QColor(hex_color)
        h, s, v, a = color.getHsv()
        v = max(0, min(255, int(v * (1 - factor))))
        darker_color = QColor.fromHsv(h, s, v, a)
        return darker_color.name()

    def save_settings_to_config(self):
        if not config.has_section('UI'):
            config.add_section('UI')
        config.set('UI', 'accent_color', accent_color)
        config.set('UI', 'theme', theme)

        if not config.has_section('Security'):
            config.add_section('Security')
        config.set('Security', 'evil_twin_enabled', str(evil_twin_enabled))

        with open(CONFIG_FILE, 'w', encoding='utf-8') as configfile:
            config.write(configfile)

if __name__ == '__main__':
    app = QApplication([])
    ex = WiFiApp()
    ex.show()
    sys.exit(app.exec_())