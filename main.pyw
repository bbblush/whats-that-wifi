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
language = config.get('UI', 'language', fallback='en')

COLOR_MAP = {
    'Green': "#28722A",
    'Purple': "#842395",
    'White': '#FFFFFF',
    'Blue': "#175C95",
    'Yellow': "#B6A82B",
    'Red': "#BA372D"
}

THEME_MAP = {
    'light': 'light',
    'dark': 'dark',
    'oled': 'oled'
}

COLOR_LABELS = {
    'en': {
        'Green': 'Green',
        'Purple': 'Purple',
        'White': 'White',
        'Blue': 'Blue',
        'Yellow': 'Yellow',
        'Red': 'Red',
    },
    'ru': {
        'Green': 'Зелёный',
        'Purple': 'Фиолетовый',
        'White': 'Белый',
        'Blue': 'Синий',
        'Yellow': 'Жёлтый',
        'Red': 'Красный',
    },
}

THEME_LABELS = {
    'en': {
        'light': 'Light',
        'dark': 'Dark',
        'oled': 'OLED (Black)',
    },
    'ru': {
        'light': 'Светлая',
        'dark': 'Тёмная',
        'oled': 'OLED (Чёрная)',
    },
}

LANG_LABELS = {
    'en': 'English',
    'ru': 'Русский',
}

TRANSLATIONS = {
    'en': {
        'app_title': "What's-that-WiFi?",
        'scan_button': "Scan Nearby Networks",
        'connect_button': "Connect",
        'analysis_progress': "Analysis progress: %p%",
        'details_placeholder': "Click a network to view details",
        'details_scanning': "Scanning...",
        'vendor_checking': "Vendor: Checking...",
        'vendor_failed': "Vendor: Failed ({points} points)",
        'vendor_line': "Vendor: {vendor} ({points} points)",
        'encryption_line': "Encryption type: {encryption} ({points} points)",
        'signal_line': "Signal strength: {signal}% ({points} points)",
        'channel_width_line': "Channel width: {channel_width} ({points} points)",
        'wifi_standard_line': "Wi-Fi standard: {standard} ({points} points)",
        'frequency_band_line': "Frequency band: {frequency} ({points} points)",
        'evil_twin_detected': "Evil Twin attack detected (BSSID mismatch)! ({points} points)",
        'evil_twin_linked': " Linked to: SSID '{ssid}', BSSID '{bssid}'",
        'evil_twin_none': "No Evil Twin attack detected (0 points)",
        'connected_devices_many': "Connected devices: {count} (-5 points)",
        'connected_devices_few': "Connected devices: {count} (+5 points)",
        'connected_devices_unknown': "Connected devices not determined (0 points)",
        'total_score': "Total score: {score}",
        'error_scan': "Error scanning networks: {error}",
        'error_check_current': "Error checking current connection: {error}",
        'tray_unavailable': "System tray is not available on this system.",
        'tray_minimized': "The application has been minimized to the tray",
        'tray_open': "Open",
        'tray_exit': "Exit",
        'sidebar_about': "About",
        'sidebar_networks': "Networks",
        'sidebar_settings': "Settings",
        'sidebar_exit': "Exit",
        'exit_title': "Exit",
        'exit_prompt': "Do you want to exit the application or minimize it to the tray?",
        'exit_action': "Exit",
        'minimize_action': "Minimize (tray)",
        'cancel_action': "Cancel",
        'connect_title': "Connect",
        'connect_ssid_missing': "SSID not found for this network.",
        'connect_connecting': "Connecting to '{ssid}'...",
        'connect_password_title': "Wi-Fi Password",
        'connect_password_prompt': "Enter password for '{ssid}':",
        'profile_add_failed': "Failed to add Wi-Fi profile.",
        'connect_failed': "Failed to connect with the new profile.",
        'profile_create_failed': "Failed to create Wi-Fi profile.",
        'notify_crit': "Network '{ssid}' is critically unsafe! Score: {score}",
        'notify_unsafe': "Network '{ssid}' is unsafe. Score: {score}",
        'notify_rel_safe': "Network '{ssid}' is relatively safe. Score: {score}",
        'notify_safe': "Network '{ssid}' is safe. Score: {score}",
        'notify_abs_safe': "Network '{ssid}' is absolutely safe. Score: {score}",
        'settings_accent': "Accent color:",
        'settings_theme': "Theme:",
        'settings_security': "Security check:",
        'settings_evil_twin': "Enable Evil Twin detection (recommended)",
        'settings_language': "Language:",
        'warning_evil_twin': "⚠️ Disabling Evil Twin detection makes you vulnerable to Wi-Fi spoofing attacks!",
        'about_title': "What's-that-WiFi?",
        'about_html': "<h2>About the application</h2><p><b>Version:</b> 0.2.2, MultiLanguage Edition</p><p><b>Developer:</b> bbblush</p><p>Application for analyzing Wi-Fi network security.</p>",
        'app_icon_label': "App Icon",
        'unknown_ssid': "Unknown",
        'vendor_status_known': "known",
        'vendor_status_unknown': "unknown",
        'vendor_status_failed': "Failed",
    },
    'ru': {
        'app_title': "What's-that-WiFi?",
        'scan_button': "Сканировать сети",
        'connect_button': "Подключиться",
        'analysis_progress': "Прогресс анализа: %p%",
        'details_placeholder': "Выберите сеть, чтобы увидеть детали",
        'details_scanning': "Сканирование...",
        'vendor_checking': "Вендор: Проверка...",
        'vendor_failed': "Вендор: Ошибка ({points} баллов)",
        'vendor_line': "Вендор: {vendor} ({points} баллов)",
        'encryption_line': "Тип шифрования: {encryption} ({points} баллов)",
        'signal_line': "Сигнал: {signal}% ({points} баллов)",
        'channel_width_line': "Ширина канала: {channel_width} ({points} баллов)",
        'wifi_standard_line': "Стандарт Wi-Fi: {standard} ({points} баллов)",
        'frequency_band_line': "Диапазон: {frequency} ({points} баллов)",
        'evil_twin_detected': "Обнаружен Evil Twin (BSSID не совпадает)! ({points} баллов)",
        'evil_twin_linked': " Связано с: SSID '{ssid}', BSSID '{bssid}'",
        'evil_twin_none': "Evil Twin не обнаружен (0 баллов)",
        'connected_devices_many': "Подключенные устройства: {count} (-5 баллов)",
        'connected_devices_few': "Подключенные устройства: {count} (+5 баллов)",
        'connected_devices_unknown': "Подключенные устройства не определены (0 баллов)",
        'total_score': "Итоговый балл: {score}",
        'error_scan': "Ошибка сканирования сетей: {error}",
        'error_check_current': "Ошибка проверки текущего подключения: {error}",
        'tray_unavailable': "Системный трей недоступен.",
        'tray_minimized': "Приложение свернуто в трей",
        'tray_open': "Открыть",
        'tray_exit': "Выход",
        'sidebar_about': "О приложении",
        'sidebar_networks': "Сети",
        'sidebar_settings': "Настройки",
        'sidebar_exit': "Выход",
        'exit_title': "Выход",
        'exit_prompt': "Выйти из приложения или свернуть в трей?",
        'exit_action': "Выйти",
        'minimize_action': "Свернуть в трей",
        'cancel_action': "Отмена",
        'connect_title': "Подключение",
        'connect_ssid_missing': "SSID для этой сети не найден.",
        'connect_connecting': "Подключение к '{ssid}'...",
        'connect_password_title': "Пароль Wi-Fi",
        'connect_password_prompt': "Введите пароль для '{ssid}':",
        'profile_add_failed': "Не удалось добавить профиль Wi-Fi.",
        'connect_failed': "Не удалось подключиться с новым профилем.",
        'profile_create_failed': "Не удалось создать профиль Wi-Fi.",
        'notify_crit': "Сеть '{ssid}' крайне небезопасна! Балл: {score}",
        'notify_unsafe': "Сеть '{ssid}' небезопасна. Балл: {score}",
        'notify_rel_safe': "Сеть '{ssid}' относительно безопасна. Балл: {score}",
        'notify_safe': "Сеть '{ssid}' безопасна. Балл: {score}",
        'notify_abs_safe': "Сеть '{ssid}' абсолютно безопасна. Балл: {score}",
        'settings_accent': "Акцентный цвет:",
        'settings_theme': "Тема:",
        'settings_security': "Проверка безопасности:",
        'settings_evil_twin': "Включить проверку Evil Twin (рекомендуется)",
        'settings_language': "Язык:",
        'warning_evil_twin': "⚠️ Отключение проверки Evil Twin делает вас уязвимыми к подмене Wi‑Fi!",
        'about_title': "What's-that-WiFi?",
        'about_html': "<h2>О приложении</h2><p><b>Версия:</b> 0.2.2, MultiLanguage Edition</p><p><b>Разработчик:</b> bbblush</p><p>Приложение для анализа безопасности Wi‑Fi сетей.</p>",
        'app_icon_label': "Иконка приложения",
        'unknown_ssid': "Неизвестно",
        'vendor_status_known': "известен",
        'vendor_status_unknown': "неизвестен",
        'vendor_status_failed': "Ошибка",
    },
}

def t(key, **kwargs):
    table = TRANSLATIONS.get(language, TRANSLATIONS['en'])
    text = table.get(key, TRANSLATIONS['en'].get(key, key))
    if kwargs:
        return text.format(**kwargs)
    return text

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
                title=t('app_title'),
                message=t('error_scan', error=e),
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
        details['encryption'] = t('encryption_line', encryption=encryption, points=sec_bal['encryption'][encryption_key])

        signal = network.get("signal", 0)
        signal_score = self.analyze_signal_strength(signal)
        bal += signal_score
        details['signal'] = t('signal_line', signal=signal, points=signal_score)

        channel_width = network.get("channel_width", "20 MHz")
        channel_width_score = self.analyze_channel_width(channel_width)
        bal += channel_width_score
        details['channel_width'] = t('channel_width_line', channel_width=channel_width, points=channel_width_score)

        standard = network.get("wifi_standard", "802.11n")
        standard_score = self.analyze_wifi_standard(standard)
        bal += standard_score
        details['wifi_standard'] = t('wifi_standard_line', standard=standard, points=standard_score)

        frequency = network.get("frequency", "2.4 GHz")
        frequency_score = self.analyze_frequency_band(frequency)
        bal += frequency_score
        details['frequency_band'] = t('frequency_band_line', frequency=frequency, points=frequency_score)

        bssid = network.get("bssid")
        ssid = network.get("ssid")

        evil_twin_result = self.check_evil_twin(ssid, bssid)
        if evil_twin_result['is_evil_twin']:
             bal += sec_bal['evil_twin']['bssid_mismatch_both_checks']
             details['evil_twin'] = t('evil_twin_detected', points=sec_bal['evil_twin']['bssid_mismatch_both_checks'])
             details['evil_twin'] += t('evil_twin_linked', ssid=evil_twin_result['matched_ssid'], bssid=evil_twin_result['matched_bssid'])
        else:
            details['evil_twin'] = t('evil_twin_none')

        vendor_status = network.get("vendor_status", "unknown")
        vendor_pending = False
        if vendor_status == "checking":
            vendor_pending = True
            details['vendor'] = t('vendor_checking')
        elif vendor_status == "failed":
            bal += sec_bal['vendor'].get('unknown', 0)
            details['vendor'] = t('vendor_failed', points=sec_bal['vendor']['unknown'])
        else:
            bal += sec_bal['vendor'].get(vendor_status, 0)
            vendor_label = t(f'vendor_status_{vendor_status}')
            details['vendor'] = t('vendor_line', vendor=vendor_label, points=sec_bal['vendor'][vendor_status])

        connected_devices = network.get("connected_devices", 0)
        if connected_devices > 10:
            bal -= 5
            details["connected_devices"] = t('connected_devices_many', count=connected_devices)
        elif (connected_devices <= 5) and (connected_devices >= 0):
            bal += 5
            details["connected_devices"] = t('connected_devices_few', count=connected_devices)
        elif connected_devices == -1:
            details["connected_devices"] = t('connected_devices_unknown')

        details['total_score'] = t('total_score', score=bal)
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
        self.progress_bar.setFormat(t('analysis_progress'))
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
        self.details_text.setHtml(f"<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>{t('details_placeholder')}</div>")
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
        self.scan_button = QPushButton(t('scan_button'))
        self.scan_button.setMinimumHeight(50)
        self.scan_button.clicked.connect(self.update_networks)
        self.scan_button.pressed.connect(self.on_scan_pressed)
        self.scan_button.released.connect(self.on_scan_released)
        button_layout.addWidget(self.scan_button, stretch=8)
        self.scan_shadow = apply_shadow(self.scan_button, radius=18, color=QColor(0, 0, 0, 110), offset=(0, 6))

        self.connect_button = QPushButton(t('connect_button'))
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
        self.details_text.setHtml(f"<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>{t('details_scanning')}</div>")

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
            ssid = network.get('ssid', t('unknown_ssid'))
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

        self.details_text.setHtml(f"<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>{t('details_placeholder')}</div>")

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
                    ssid = network.get("ssid", t('unknown_ssid'))
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

    def apply_language(self):
        self.progress_bar.setFormat(t('analysis_progress'))
        self.scan_button.setText(t('scan_button'))
        self.connect_button.setText(t('connect_button'))
        for i in range(self.network_list.count()):
            item = self.network_list.item(i)
            meta = item.data(Qt.UserRole) or {}
            bssid = meta.get("bssid")
            network = None
            if bssid:
                network = next((n for n in self.analyzer.networks if n.get("bssid") == bssid), None)
            if network:
                bal, _, vendor_pending = self.analyzer.analyze_network(network)
                ssid = network.get("ssid", t('unknown_ssid'))
                item.setText(f"{ssid} - {bal}")
                meta["pending_vendor"] = vendor_pending
                item.setData(Qt.UserRole, meta)
        if self.current_network:
            _, details, _ = self.analyzer.analyze_network(self.current_network)
            details_text_content = "\n".join(details.values())
            self.details_text.setText(details_text_content)
        else:
            self.details_text.setHtml(f"<div style='text-align: center; vertical-align: middle; height: 100%; display: table-cell;'>{t('details_placeholder')}</div>")
    def on_connect_clicked(self):
        network = self.current_network
        if not network:
            return
        ssid = network.get("ssid")
        if not ssid:
            QMessageBox.warning(self, t('connect_title'), t('connect_ssid_missing'))
            return

        if self.app_instance.try_connect_existing(ssid):
            QMessageBox.information(self, t('connect_title'), t('connect_connecting', ssid=ssid))
            return

        encryption = (network.get("encryption") or "").lower()
        is_open = "open" in encryption or "открыт" in encryption or "none" in encryption

        if not is_open:
            password, ok = QInputDialog.getText(self, t('connect_password_title'), t('connect_password_prompt', ssid=ssid), QLineEdit.Password)
            if not ok:
                return
        else:
            password = ""

        success, message = self.app_instance.create_profile_and_connect(ssid, password, is_open)
        if success:
            QMessageBox.information(self, t('connect_title'), message)
        else:
            QMessageBox.warning(self, t('connect_title'), message)

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
        self.accent_color_combo.currentIndexChanged.connect(self.on_accent_color_changed)
        self.accent_label = QLabel()
        layout.addRow(self.accent_label, self.accent_color_combo)

        self.theme_combo = QComboBox()
        self.theme_combo.currentIndexChanged.connect(self.on_theme_changed)
        self.theme_label = QLabel()
        layout.addRow(self.theme_label, self.theme_combo)

        self.evil_twin_checkbox = QCheckBox()
        self.evil_twin_checkbox.setChecked(evil_twin_enabled)
        self.evil_twin_checkbox.stateChanged.connect(self.on_evil_twin_toggled)
        self.security_label = QLabel()
        layout.addRow(self.security_label, self.evil_twin_checkbox)

        self.warning_label = QLabel()
        self.warning_label.setStyleSheet("color: #F44336; font-weight: bold;")
        self.warning_label.setWordWrap(True)
        layout.addRow("", self.warning_label)

        self.language_combo = QComboBox()
        self.language_combo.currentIndexChanged.connect(self.on_language_changed)
        self.language_label = QLabel()
        layout.addRow(self.language_label, self.language_combo)

        self.apply_language()

        self.setLayout(layout)

    def apply_language(self):
        self.accent_label.setText(t('settings_accent'))
        self.theme_label.setText(t('settings_theme'))
        self.security_label.setText(t('settings_security'))
        self.evil_twin_checkbox.setText(t('settings_evil_twin'))
        self.warning_label.setText(t('warning_evil_twin'))
        self.language_label.setText(t('settings_language'))
        self.populate_accent_colors()
        self.populate_themes()
        self.populate_languages()

    def populate_accent_colors(self):
        self.accent_color_combo.blockSignals(True)
        self.accent_color_combo.clear()
        labels = COLOR_LABELS.get(language, COLOR_LABELS['en'])
        for key in COLOR_MAP.keys():
            self.accent_color_combo.addItem(labels.get(key, key), key)
        current_key = next((name for name, color in COLOR_MAP.items() if color == accent_color), 'Green')
        idx = self.accent_color_combo.findData(current_key)
        if idx >= 0:
            self.accent_color_combo.setCurrentIndex(idx)
        self.accent_color_combo.blockSignals(False)

    def populate_themes(self):
        self.theme_combo.blockSignals(True)
        self.theme_combo.clear()
        labels = THEME_LABELS.get(language, THEME_LABELS['en'])
        for key in THEME_MAP.keys():
            self.theme_combo.addItem(labels.get(key, key), key)
        idx = self.theme_combo.findData(theme)
        if idx >= 0:
            self.theme_combo.setCurrentIndex(idx)
        self.theme_combo.blockSignals(False)

    def populate_languages(self):
        self.language_combo.blockSignals(True)
        self.language_combo.clear()
        for code in LANG_LABELS.keys():
            label = LANG_LABELS.get(code, code)
            self.language_combo.addItem(label, code)
        idx = self.language_combo.findData(language)
        if idx >= 0:
            self.language_combo.setCurrentIndex(idx)
        self.language_combo.blockSignals(False)

    def on_accent_color_changed(self):
        global accent_color
        color_key = self.accent_color_combo.currentData()
        new_color = COLOR_MAP.get(color_key, '#4CAF50')
        accent_color = new_color
        self.app_instance.apply_accent_color(accent_color)

    def on_theme_changed(self):
        global theme
        theme_key = self.theme_combo.currentData()
        new_theme = THEME_MAP.get(theme_key, 'dark')
        theme = new_theme
        self.app_instance.apply_accent_color(accent_color)

    def on_evil_twin_toggled(self, state):
        global evil_twin_enabled
        evil_twin_enabled = (state == Qt.Checked)
        self.app_instance.save_settings_to_config()

    def on_language_changed(self):
        global language
        new_language = self.language_combo.currentData()
        if new_language and new_language != language:
            language = new_language
            self.app_instance.apply_language()
            self.app_instance.save_settings_to_config()

class AboutWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
        layout.addWidget(self.title_label, alignment=Qt.AlignCenter)

        self.icon_label = QLabel()
        icon_path = resource_path("icon.png")
        if os.path.exists(icon_path):
            pixmap = QPixmap(icon_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.icon_label.setPixmap(scaled_pixmap)
            else:
                self.icon_label.setText(t('app_icon_label'))
        else:
            self.icon_label.setText(t('app_icon_label'))
        self.icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.icon_label)

        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setMaximumHeight(200)
        layout.addWidget(self.info_text)

        self.setLayout(layout)
        self.apply_language()

    def apply_language(self):
        self.title_label.setText(t('about_title'))
        self.info_text.setHtml(t('about_html'))
        if self.icon_label.pixmap() is None or self.icon_label.pixmap().isNull():
            self.icon_label.setText(t('app_icon_label'))

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
        self.apply_language()

    def initUI(self):
        self.setWindowTitle(t('app_title'))
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

        self.about_item = QListWidgetItem(QIcon(resource_path("icon.png")), t('sidebar_about'))
        self.about_item.setToolTip(t('sidebar_about'))
        self.sidebar.addItem(self.about_item)

        separator1 = QListWidgetItem()
        separator1.setFlags(Qt.NoItemFlags)
        separator1.setText("---------------")
        self.sidebar.addItem(separator1)

        self.networks_item = QListWidgetItem(QIcon(resource_path("wifi_icon.png")), t('sidebar_networks'))
        self.networks_item.setToolTip(t('sidebar_networks'))
        self.sidebar.addItem(self.networks_item)

        self.settings_item = QListWidgetItem(QIcon(resource_path("settings_icon.png")), t('sidebar_settings'))
        self.settings_item.setToolTip(t('sidebar_settings'))
        self.sidebar.addItem(self.settings_item)

        separator2 = QListWidgetItem()
        separator2.setFlags(Qt.NoItemFlags)
        separator2.setText("---------------")
        self.sidebar.addItem(separator2)

        self.exit_item = QListWidgetItem(QIcon(resource_path("exit_icon.png")), t('sidebar_exit'))
        self.exit_item.setToolTip(t('sidebar_exit'))
        self.sidebar.addItem(self.exit_item)

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

    def apply_language(self):
        self.setWindowTitle(t('app_title'))
        self.about_item.setText(t('sidebar_about'))
        self.about_item.setToolTip(t('sidebar_about'))
        self.networks_item.setText(t('sidebar_networks'))
        self.networks_item.setToolTip(t('sidebar_networks'))
        self.settings_item.setText(t('sidebar_settings'))
        self.settings_item.setToolTip(t('sidebar_settings'))
        self.exit_item.setText(t('sidebar_exit'))
        self.exit_item.setToolTip(t('sidebar_exit'))
        self.networks_widget.apply_language()
        self.settings_widget.apply_language()
        self.about_widget.apply_language()
        if hasattr(self, "restore_action"):
            self.restore_action.setText(t('tray_open'))
        if hasattr(self, "quit_action"):
            self.quit_action.setText(t('tray_exit'))

    def ask_exit_or_minimize(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(t('exit_title'))
        msg_box.setText(t('exit_prompt'))
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setWindowFlags(msg_box.windowFlags() & ~Qt.WindowCloseButtonHint)

        yes_button = msg_box.button(QMessageBox.Yes)
        if yes_button:
            yes_button.setText(t('exit_action'))
            yes_button.setIcon(self.style().standardIcon(QStyle.SP_DialogCloseButton))
        no_button = msg_box.button(QMessageBox.No)
        if no_button:
            no_button.setText(t('minimize_action'))
            no_button.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMinButton))

        result = msg_box.exec_()

        if result == QMessageBox.Yes:
            QApplication.quit()
        elif result == QMessageBox.No:
            self.hide()
            self.tray_icon.showMessage(
                t('app_title'),
                t('tray_minimized'),
                QSystemTrayIcon.Information,
                2000
            )

    def create_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            notification.notify(
                title=t('app_title'),
                message=t('tray_unavailable'),
            )
            return
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(resource_path("icon.png")))
        menu = QMenu()
        self.restore_action = QAction(t('tray_open'), self)
        self.restore_action.triggered.connect(self.show)
        self.quit_action = QAction(t('tray_exit'), self)
        self.quit_action.triggered.connect(self.close_application)
        menu.addAction(self.restore_action)
        menu.addAction(self.quit_action)
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
                title=t('app_title'),
                message=t('error_check_current', error=e)
            )

    def send_notification(self, ssid, bal):
        if bal <= 10:
            message = t('notify_crit', ssid=ssid, score=bal)
        if (bal > -10) and (bal <= 0):
            message = t('notify_unsafe', ssid=ssid, score=bal)
        if (bal > 0) and (bal <= 10):
            message = t('notify_rel_safe', ssid=ssid, score=bal)
        if (bal > 10) and (bal <= 20):
            message = t('notify_safe', ssid=ssid, score=bal)
        if bal > 20:
            message = t('notify_abs_safe', ssid=ssid, score=bal)

        notification.notify(
            title=t('app_title'),
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
                return False, t('profile_add_failed')
            conn_res = subprocess.run(['netsh', 'wlan', 'connect', f'name={ssid}'],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            if conn_res.returncode == 0:
                return True, t('connect_connecting', ssid=ssid)
            return False, t('connect_failed')
        except Exception:
            return False, t('profile_create_failed')
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
        config.set('UI', 'language', language)

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
