import sys
import subprocess
import requests
import time
from fuzzywuzzy import fuzz
from PyQt5.QtWidgets import (QApplication, QHBoxLayout, QMainWindow, QListWidget, QListWidgetItem,
                             QLabel, QStyle, QVBoxLayout, QWidget, QPushButton, QTextEdit, QAction, QMenu,
                             QMessageBox, QSystemTrayIcon, QStackedWidget, QComboBox, QFormLayout, QScrollArea, QStyledItemDelegate, QCheckBox, QProgressBar, QInputDialog, QLineEdit, QGraphicsDropShadowEffect, QGraphicsOpacityEffect)
from PyQt5.QtGui import QIcon, QColor, QPalette, QPixmap, QPen, QPainter
from PyQt5.QtCore import QTimer, Qt, QSize, QObject, pyqtSignal, QRunnable, QThreadPool, QPropertyAnimation, QEasingCurve, QRect, pyqtProperty
from plyer import notification
import configparser
import os
import locale
import tempfile

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

def resource_path(filename):
    return os.path.join(DATA_DIR, filename)

CONFIG_FILE = os.path.join(DATA_DIR, "settings.cfg")

def apply_shadow(widget, radius=16, color=QColor(0, 0, 0, 90), offset=(0, 4)):
    effect = QGraphicsDropShadowEffect()
    effect.setBlurRadius(radius)
    effect.setColor(color)
    effect.setOffset(offset[0], offset[1])
    widget.setGraphicsEffect(effect)
    return effect

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
        self.vendor_statuses = {}

    def scan_networks(self):
        try:
            res = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            out = res.stdout.decode(locale.getpreferredencoding(False), errors='replace')
            networks = self.parse_netsh_output(out)
            for network in networks:
                bssid = network.get("bssid")
                if bssid and bssid in self.vendor_statuses:
                    network["vendor_status"] = self.vendor_statuses[bssid]
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

        vendor_status = network.get("vendor_status", "unknown")
        vendor_pending = False
        if vendor_status == "checking":
            vendor_pending = True
            details['vendor'] = "Vendor: Checking..."
        elif vendor_status == "failed":
            bal += sec_bal['vendor'].get('unknown', 0)
            details['vendor'] = f"Vendor: Failed ({sec_bal['vendor']['unknown']} points)"
        else:
            bal += sec_bal['vendor'].get(vendor_status, 0)
            details['vendor'] = f"Vendor: {vendor_status} ({sec_bal['vendor'][vendor_status]} points)"

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
        return bal, details, vendor_pending

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
            return 'unknown'
        except Exception:
            return 'failed'

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
        meta = index.data(Qt.UserRole)
        pending_vendor = isinstance(meta, dict) and meta.get("pending_vendor", False)
        try:
            score = int(text.split(" - ")[1])
        except (IndexError, ValueError):
            score = 0
        if pending_vendor:
            score_color = QColor("#DDDDDD")
        else:
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

class SidebarListWidget(QListWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._indicator_rect = QRect()
        self._indicator_anim = QPropertyAnimation(self, b"indicatorRect")
        self._indicator_anim.setDuration(220)
        self._indicator_anim.setEasingCurve(QEasingCurve.InOutCubic)
        self._first_layout = True
        self._first_offset = 26

    def indicatorRect(self):
        return self._indicator_rect

    def setIndicatorRect(self, rect):
        self._indicator_rect = rect
        self.viewport().update()

    indicatorRect = pyqtProperty(QRect, fget=indicatorRect, fset=setIndicatorRect)

    def animate_indicator_to_current(self, animated=True):
        item = self.currentItem()
        if not item:
            return
        rect = self.visualItemRect(item)
        if rect.isNull():
            return
        inset_x = 2
        inset_y = 4
        y_offset = 2
        target = QRect(
            rect.x() + inset_x,
            rect.y() + inset_y + y_offset,
            rect.width() - inset_x * 2,
            rect.height() - inset_y * 1
        )
        if self._first_layout:
            target = target.translated(0, self._first_offset)
            self._first_layout = False
        if animated:
            self._indicator_anim.stop()
            self._indicator_anim.setStartValue(self._indicator_rect)
            self._indicator_anim.setEndValue(target)
            self._indicator_anim.start()
        else:
            self.setIndicatorRect(target)

    def paintEvent(self, event):
        if not self._indicator_rect.isNull():
            painter = QPainter(self.viewport())
            painter.setRenderHint(QPainter.Antialiasing, True)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(accent_color))
            painter.drawRoundedRect(self._indicator_rect, 6, 6)
            painter.end()
        super().paintEvent(event)

class VendorLookupSignals(QObject):
    finished = pyqtSignal(str, str)

class VendorLookupTask(QRunnable):
    def __init__(self, analyzer, bssid):
        super().__init__()
        self.analyzer = analyzer
        self.bssid = bssid
        self.signals = VendorLookupSignals()

    def run(self):
        status = self.analyzer.check_vendor(self.bssid)
        self.signals.finished.emit(self.bssid, status)

class NetworksWidget(QWidget):
    def __init__(self, analyzer, app_instance):
        super().__init__()
        self.analyzer = analyzer
        self.app_instance = app_instance
        self.threadpool = QThreadPool.globalInstance()
        self.vendor_tasks_in_flight = set()
        self.vendor_tasks_total = 0
        self.vendor_tasks_completed = 0
        self.current_network = None
        self.initUI()

    def initUI(self):
        outer_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Analysis progress: %p%")
        outer_layout.addWidget(self.progress_bar)

        main_layout = QHBoxLayout()
        self.network_list = QListWidget()
        self.network_list.setItemDelegate(ScoreDelegate())
        self.network_list.itemClicked.connect(self.show_network_details)
        main_layout.addWidget(self.network_list, stretch=1)
        apply_shadow(self.network_list)

        right_column_layout = QVBoxLayout()
        self.details_container = QWidget()
        details_container_layout = QVBoxLayout()
        details_container_layout.setContentsMargins(0, 0, 0, 0)
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setHtml("<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>Click a network to view details</div>")
        details_container_layout.addWidget(self.details_text)
        self.details_container.setLayout(details_container_layout)
        right_column_layout.addWidget(self.details_container, stretch=4)
        apply_shadow(self.details_container)
        self.details_opacity = QGraphicsOpacityEffect(self.details_container)
        self.details_container.setGraphicsEffect(self.details_opacity)
        self.details_opacity.setOpacity(1.0)
        self.details_fade = QPropertyAnimation(self.details_opacity, b"opacity")
        self.details_fade.setDuration(180)
        self.details_fade.setEasingCurve(QEasingCurve.InOutQuad)

        button_layout = QHBoxLayout()
        self.scan_button = QPushButton('Scan Nearby Networks')
        self.scan_button.setMinimumHeight(50)
        self.scan_button.clicked.connect(self.update_networks)
        self.scan_button.pressed.connect(self.on_scan_pressed)
        self.scan_button.released.connect(self.on_scan_released)
        button_layout.addWidget(self.scan_button, stretch=8)
        self.scan_shadow = apply_shadow(self.scan_button, radius=18, color=QColor(0, 0, 0, 110), offset=(0, 6))

        self.connect_button = QPushButton('Connect')
        self.connect_button.setMinimumHeight(40)
        self.connect_button.setEnabled(False)
        self.connect_button.clicked.connect(self.on_connect_clicked)
        self.connect_button.pressed.connect(self.on_connect_pressed)
        self.connect_button.released.connect(self.on_connect_released)
        button_layout.addWidget(self.connect_button, stretch=4)
        self.connect_shadow = apply_shadow(self.connect_button, radius=18, color=QColor(0, 0, 0, 110), offset=(0, 6))

        right_column_layout.addLayout(button_layout, stretch=1)
        main_layout.addLayout(right_column_layout, stretch=1)
        outer_layout.addLayout(main_layout)
        self.setLayout(outer_layout)

    def update_networks(self):
        self.details_text.setHtml("<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>Scanning...</div>")

        self.analyzer.scan_networks()

        self.network_list.clear()
        self.vendor_tasks_in_flight.clear()
        self.vendor_tasks_total = 0
        self.vendor_tasks_completed = 0

        pending_bssids = set()
        for network in self.analyzer.networks:
            bssid = network.get("bssid")
            if "vendor_status" not in network:
                if bssid and self.analyzer.is_valid_bssid(bssid):
                    network["vendor_status"] = "checking"
                else:
                    network["vendor_status"] = "unknown"

            bal, _, vendor_pending = self.analyzer.analyze_network(network)
            ssid = network.get('ssid', 'Unknown')
            item_text = f"{ssid} - {bal}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, {"ssid": ssid, "bssid": bssid, "pending_vendor": vendor_pending})
            self.network_list.addItem(item)

            if vendor_pending and bssid:
                pending_bssids.add(bssid)

        self.vendor_tasks_total = len(pending_bssids)
        if self.vendor_tasks_total == 0:
            self.progress_bar.setValue(100)
        else:
            self.progress_bar.setValue(50)
            for bssid in pending_bssids:
                self.vendor_tasks_in_flight.add(bssid)
                task = VendorLookupTask(self.analyzer, bssid)
                task.signals.finished.connect(self.on_vendor_checked)
                self.threadpool.start(task)

        self.details_text.setHtml("<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>Click a network to view details</div>")

    def on_scan_pressed(self):
        if not hasattr(self, "scan_button_anim"):
            self.scan_button_anim = QPropertyAnimation(self.scan_button, b"geometry")
            self.scan_button_anim.setDuration(90)
            self.scan_button_anim.setEasingCurve(QEasingCurve.OutQuad)
        if hasattr(self, "scan_shadow") and self.scan_shadow is not None:
            self.scan_shadow.setEnabled(False)
        self._scan_button_geom = self.scan_button.geometry()
        rect = self._scan_button_geom
        shrink = 4
        target = QRect(rect.x() + shrink, rect.y() + shrink, rect.width() - shrink * 2, rect.height() - shrink * 2)
        self.scan_button_anim.stop()
        self.scan_button_anim.setStartValue(rect)
        self.scan_button_anim.setEndValue(target)
        self.scan_button_anim.start()

    def on_scan_released(self):
        if not hasattr(self, "scan_button_anim"):
            return
        if hasattr(self, "scan_shadow") and self.scan_shadow is not None:
            self.scan_shadow.setEnabled(True)
        rect = getattr(self, "_scan_button_geom", self.scan_button.geometry())
        self.scan_button_anim.stop()
        self.scan_button_anim.setStartValue(self.scan_button.geometry())
        self.scan_button_anim.setEndValue(rect)
        self.scan_button_anim.start()

    def on_connect_pressed(self):
        if hasattr(self, "connect_shadow") and self.connect_shadow is not None:
            self.connect_shadow.setEnabled(False)

    def on_connect_released(self):
        if hasattr(self, "connect_shadow") and self.connect_shadow is not None:
            self.connect_shadow.setEnabled(True)

    def on_vendor_checked(self, bssid, status):
        if bssid in self.vendor_tasks_in_flight:
            self.vendor_tasks_in_flight.remove(bssid)
            self.vendor_tasks_completed += 1
            if self.vendor_tasks_total > 0:
                progress = 50 + int(50 * (self.vendor_tasks_completed / self.vendor_tasks_total))
                self.progress_bar.setValue(min(100, progress))
            else:
                self.progress_bar.setValue(100)
        self.analyzer.vendor_statuses[bssid] = status
        for network in self.analyzer.networks:
            if network.get("bssid") == bssid:
                network["vendor_status"] = status

        for i in range(self.network_list.count()):
            item = self.network_list.item(i)
            meta = item.data(Qt.UserRole) or {}
            if meta.get("bssid") == bssid:
                network = next((n for n in self.analyzer.networks if n.get("bssid") == bssid), None)
                if network:
                    bal, _, vendor_pending = self.analyzer.analyze_network(network)
                    ssid = network.get("ssid", "Unknown")
                    item.setText(f"{ssid} - {bal}")
                    meta["pending_vendor"] = vendor_pending
                    item.setData(Qt.UserRole, meta)

        current_item = self.network_list.currentItem()
        if current_item:
            meta = current_item.data(Qt.UserRole) or {}
            if meta.get("bssid") == bssid:
                network = next((n for n in self.analyzer.networks if n.get("bssid") == bssid), None)
                if network:
                    _, details, _ = self.analyzer.analyze_network(network)
                    details_text_content = "\n".join(details.values())
                    self.details_text.setText(details_text_content)

    def show_network_details(self, item):
        meta = item.data(Qt.UserRole) or {}
        bssid = meta.get("bssid")
        if bssid:
            network = next((n for n in self.analyzer.networks if n.get("bssid") == bssid), None)
        else:
            full_text = item.text()
            ssid = full_text.split(" - ")[0]
            network = next((n for n in self.analyzer.networks if n.get("ssid") == ssid), None)
        if network:
            self.current_network = network
            self.connect_button.setEnabled(True)
            _, details, _ = self.analyzer.analyze_network(network)
            details_text_content = "\n".join(details.values())
            self.fade_details_to(details_text_content)
        else:
            self.current_network = None
            self.connect_button.setEnabled(False)

    def fade_details_to(self, text):
        self.details_fade.stop()
        self.details_fade.setStartValue(1.0)
        self.details_fade.setEndValue(0.0)
        def _after_fade_out():
            try:
                self.details_fade.finished.disconnect(_after_fade_out)
            except Exception:
                pass
            self.details_text.setText(text)
            self.details_fade.setStartValue(0.0)
            self.details_fade.setEndValue(1.0)
            self.details_fade.start()
        self.details_fade.finished.connect(_after_fade_out)
        self.details_fade.start()
    def on_connect_clicked(self):
        network = self.current_network
        if not network:
            return
        ssid = network.get("ssid")
        if not ssid:
            QMessageBox.warning(self, "Connect", "SSID not found for this network.")
            return

        if self.app_instance.try_connect_existing(ssid):
            QMessageBox.information(self, "Connect", f"Connecting to '{ssid}'...")
            return

        encryption = (network.get("encryption") or "").lower()
        is_open = "open" in encryption or "открыт" in encryption or "none" in encryption

        if not is_open:
            password, ok = QInputDialog.getText(self, "Wi-Fi Password", f"Enter password for '{ssid}':", QLineEdit.Password)
            if not ok:
                return
        else:
            password = ""

        success, message = self.app_instance.create_profile_and_connect(ssid, password, is_open)
        if success:
            QMessageBox.information(self, "Connect", message)
        else:
            QMessageBox.warning(self, "Connect", message)

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
        icon_path = resource_path("icon.png")
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
        self.setWindowIcon(QIcon(resource_path("icon.png")))
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

        self.sidebar = SidebarListWidget()
        self.sidebar.setMaximumWidth(150)
        self.sidebar.setSpacing(5)
        self.sidebar.setIconSize(QSize(24, 24))
        apply_shadow(self.sidebar, radius=18, color=QColor(0, 0, 0, 90), offset=(0, 6))

        about_item = QListWidgetItem(QIcon(resource_path("icon.png")), "About")
        about_item.setToolTip("About")
        self.sidebar.addItem(about_item)

        separator1 = QListWidgetItem()
        separator1.setFlags(Qt.NoItemFlags)
        separator1.setText("---------------")
        self.sidebar.addItem(separator1)

        networks_item = QListWidgetItem(QIcon(resource_path("wifi_icon.png")), "Networks")
        networks_item.setToolTip("Networks")
        self.sidebar.addItem(networks_item)

        settings_item = QListWidgetItem(QIcon(resource_path("settings_icon.png")), "Settings")
        settings_item.setToolTip("Settings")
        self.sidebar.addItem(settings_item)

        separator2 = QListWidgetItem()
        separator2.setFlags(Qt.NoItemFlags)
        separator2.setText("---------------")
        self.sidebar.addItem(separator2)

        exit_item = QListWidgetItem(QIcon(resource_path("exit_icon.png")), "Exit")
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
        self.sidebar.animate_indicator_to_current(animated=False)

    def on_sidebar_item_clicked(self, index):
        if index == 0:
            self.stacked_widget.setCurrentIndex(2)
        elif index == 2:
            self.stacked_widget.setCurrentIndex(0)
        elif index == 3:
            self.stacked_widget.setCurrentIndex(1)
        elif index == 5:
            self.ask_exit_or_minimize()
        self.sidebar.animate_indicator_to_current(animated=True)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.sidebar.animate_indicator_to_current(animated=False)

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
        self.tray_icon.setIcon(QIcon(resource_path("icon.png")))
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
            out = res.stdout.decode(locale.getpreferredencoding(False), errors='replace')
            ssid = None
            for line in out.split('\n'):
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":")[1].strip()
                    break
            if ssid and ssid != self.previous_ssid:
                self.previous_ssid = ssid
                network = next((n for n in self.analyzer.networks if n.get("ssid") == ssid), None)
                if network:
                    bal, _, _ = self.analyzer.analyze_network(network)
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

    def try_connect_existing(self, ssid):
        try:
            res = subprocess.run(['netsh', 'wlan', 'connect', f'name={ssid}'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
            return res.returncode == 0
        except Exception:
            return False

    def create_profile_and_connect(self, ssid, password, is_open):
        profile_xml = self._build_wlan_profile_xml(ssid, password, is_open)
        profile_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".xml", encoding="utf-8") as f:
                f.write(profile_xml)
                profile_path = f.name
            add_res = subprocess.run(['netsh', 'wlan', 'add', 'profile', f'filename={profile_path}', 'user=current'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            if add_res.returncode != 0:
                return False, "Failed to add Wi-Fi profile."
            conn_res = subprocess.run(['netsh', 'wlan', 'connect', f'name={ssid}'],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            if conn_res.returncode == 0:
                return True, f"Connecting to '{ssid}'..."
            return False, "Failed to connect with the new profile."
        except Exception:
            return False, "Failed to create Wi-Fi profile."
        finally:
            try:
                if profile_path and os.path.exists(profile_path):
                    os.remove(profile_path)
            except Exception:
                pass

    def _build_wlan_profile_xml(self, ssid, password, is_open):
        ssid_escaped = ssid.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if is_open:
            return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid_escaped}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid_escaped}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"""
        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid_escaped}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid_escaped}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"""

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
            border-radius: 8px;
        }}
        QPushButton:hover {{
            background-color: {self.darken_color(color_hex, 0.1)};
        }}
        QComboBox {{
            background-color: {list_bg};
            color: {text_color};
            border: 1px solid {border_color};
            padding: 5px;
            border-radius: 8px;
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
            border-radius: 10px;
        }}
        QTextEdit {{
            background-color: {list_bg};
            color: {text_color};
            border: 1px solid {border_color};
            border-radius: 10px;
        }}
        QListWidget::item {{
            padding: 5px;
            margin: 0px;
            border: none;
            border-radius: 6px;
        }}
        QListWidget::item:hover {{
            background-color: {self.darken_color(color_hex, 0.1)};
        }}
        QListWidget::item:!enabled {{
            color: #888888;
        }}
        QProgressBar {{
            border: 1px solid {border_color};
            border-radius: 8px;
            text-align: center;
            background-color: {list_bg};
        }}
        QProgressBar::chunk {{
            background-color: {color_hex};
            border-radius: 8px;
        }}
        """
        QApplication.instance().setStyleSheet(app_style)
        if hasattr(self, "sidebar"):
            self.sidebar.viewport().update()
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
