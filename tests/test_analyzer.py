import os
import sys
import types
import unittest
import importlib.util
import importlib.machinery
from unittest import mock


def load_app_module():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    module_path = os.path.join(repo_root, "main.pyw")
    _install_test_stubs()
    loader = importlib.machinery.SourceFileLoader("app_main", module_path)
    spec = importlib.util.spec_from_loader("app_main", loader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _install_test_stubs():
    if "fuzzywuzzy" not in sys.modules:
        fuzzywuzzy = types.ModuleType("fuzzywuzzy")
        fuzz = types.SimpleNamespace(ratio=lambda a, b: 100 if a == b else 0)
        fuzzywuzzy.fuzz = fuzz
        sys.modules["fuzzywuzzy"] = fuzzywuzzy
        sys.modules["fuzzywuzzy.fuzz"] = fuzz

    if "plyer" not in sys.modules:
        plyer = types.ModuleType("plyer")
        notification = types.SimpleNamespace(notify=lambda **kwargs: None)
        plyer.notification = notification
        sys.modules["plyer"] = plyer
        sys.modules["plyer.notification"] = notification

    if "PyQt5" not in sys.modules:
        pyqt5 = types.ModuleType("PyQt5")
        qtwidgets = types.ModuleType("PyQt5.QtWidgets")
        qtgui = types.ModuleType("PyQt5.QtGui")
        qtcore = types.ModuleType("PyQt5.QtCore")

        class _Base:
            pass

        qtwidgets.QApplication = _Base
        qtwidgets.QHBoxLayout = _Base
        qtwidgets.QMainWindow = _Base
        qtwidgets.QListWidget = _Base
        qtwidgets.QListWidgetItem = _Base
        qtwidgets.QLabel = _Base
        qtwidgets.QStyle = _Base
        qtwidgets.QVBoxLayout = _Base
        qtwidgets.QWidget = _Base
        qtwidgets.QPushButton = _Base
        qtwidgets.QTextEdit = _Base
        qtwidgets.QAction = _Base
        qtwidgets.QMenu = _Base
        qtwidgets.QMessageBox = _Base
        qtwidgets.QSystemTrayIcon = _Base
        qtwidgets.QStackedWidget = _Base
        qtwidgets.QComboBox = _Base
        qtwidgets.QFormLayout = _Base
        qtwidgets.QScrollArea = _Base
        qtwidgets.QStyledItemDelegate = _Base
        qtwidgets.QCheckBox = _Base
        qtwidgets.QProgressBar = _Base

        qtgui.QIcon = _Base
        qtgui.QColor = _Base
        qtgui.QPalette = _Base
        qtgui.QPixmap = _Base
        qtgui.QPen = _Base

        qtcore.QTimer = _Base
        qtcore.Qt = types.SimpleNamespace(UserRole=32)
        qtcore.QSize = _Base
        qtcore.QObject = _Base
        qtcore.QRunnable = _Base
        qtcore.QThreadPool = _Base
        qtcore.pyqtSignal = lambda *args, **kwargs: object()

        sys.modules["PyQt5"] = pyqt5
        sys.modules["PyQt5.QtWidgets"] = qtwidgets
        sys.modules["PyQt5.QtGui"] = qtgui
        sys.modules["PyQt5.QtCore"] = qtcore


class TestVendorStatus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_app_module()

    def test_vendor_checking_pending(self):
        analyzer = self.app.WiFiAnalyzer()
        network = {
            "ssid": "Test",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "vendor_status": "checking",
        }
        bal, details, pending = analyzer.analyze_network(network)
        self.assertTrue(pending)
        self.assertIn("Checking...", details["vendor"])

    def test_vendor_failed_not_pending(self):
        analyzer = self.app.WiFiAnalyzer()
        network = {
            "ssid": "Test",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "vendor_status": "failed",
        }
        bal, details, pending = analyzer.analyze_network(network)
        self.assertFalse(pending)
        self.assertIn("Failed", details["vendor"])

    def test_vendor_known_not_pending(self):
        analyzer = self.app.WiFiAnalyzer()
        network = {
            "ssid": "Test",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "vendor_status": "known",
        }
        bal, details, pending = analyzer.analyze_network(network)
        self.assertFalse(pending)
        self.assertIn("known", details["vendor"])


class TestCheckVendor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_app_module()

    def test_check_vendor_known(self):
        analyzer = self.app.WiFiAnalyzer()
        fake_response = mock.Mock(status_code=200, text="Vendor")
        with mock.patch.object(self.app.requests, "get", return_value=fake_response):
            self.assertEqual(analyzer.check_vendor("AA:BB:CC:DD:EE:FF"), "known")

    def test_check_vendor_unknown(self):
        analyzer = self.app.WiFiAnalyzer()
        fake_response = mock.Mock(status_code=200, text="")
        with mock.patch.object(self.app.requests, "get", return_value=fake_response):
            self.assertEqual(analyzer.check_vendor("AA:BB:CC:DD:EE:FF"), "unknown")

    def test_check_vendor_failed(self):
        analyzer = self.app.WiFiAnalyzer()
        with mock.patch.object(self.app.requests, "get", side_effect=Exception("no net")):
            self.assertEqual(analyzer.check_vendor("AA:BB:CC:DD:EE:FF"), "failed")


if __name__ == "__main__":
    unittest.main()
