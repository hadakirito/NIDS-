# test_gui.py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import unittest
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt
from Nids import NIDSMainWindow

class TestNIDSMainWindow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    def setUp(self):
        self.main_window = NIDSMainWindow()

    def test_start_stop_buttons(self):
        self.main_window.interfaceComboBox.addItem('eth0')
        self.main_window.interfaceComboBox.setCurrentIndex(0)
        QTest.mouseClick(self.main_window.startButton, Qt.LeftButton)
        self.assertEqual(self.main_window.statusLabel.text(), 'Status: Capturing...')

        QTest.mouseClick(self.main_window.stopButton, Qt.LeftButton)
        status_text = self.main_window.statusLabel.text()
        self.assertTrue(status_text in ['Status: Stopped', 'Status: Error stopping capture: Unsupported (offline or unsupported socket)'])

    def test_clear_button(self):
        self.main_window.packetDisplay.setText("Sample Packet")
        self.main_window.intrusionDisplay.setText("Sample Alert")
        QTest.mouseClick(self.main_window.clearButton, Qt.LeftButton)
        self.assertEqual(self.main_window.packetDisplay.toPlainText(), "")
        self.assertEqual(self.main_window.intrusionDisplay.toPlainText(), "")

    def test_save_button(self):
        self.main_window.packet_analyzer.captured_packets = ['sample_packet']
        QTest.mouseClick(self.main_window.saveButton, Qt.LeftButton)
        # Further implementation needed to mock file dialogs and file system

    @classmethod
    def tearDownClass(cls):
        cls.app.exit()

if __name__ == '__main__':
    unittest.main()
