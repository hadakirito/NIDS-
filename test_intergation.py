# test_integration.py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import unittest
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt
from scapy.all import Ether, IP, TCP
from Nids import NIDSMainWindow

class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication([])

    def setUp(self):
        self.main_window = NIDSMainWindow()

    def test_full_workflow(self):
        self.main_window.interfaceComboBox.addItem('eth0')
        self.main_window.interfaceComboBox.setCurrentIndex(0)
        QTest.mouseClick(self.main_window.startButton, Qt.LeftButton)
        self.assertEqual(self.main_window.statusLabel.text(), 'Status: Capturing...')

        # Simulate packet capture
        packet = Ether()/IP(src='192.168.1.1')/TCP(flags='S')
        self.main_window.packet_analyzer.analyze(packet)
        self.assertIn("TCP", self.main_window.packetDisplay.toPlainText())

        QTest.mouseClick(self.main_window.stopButton, Qt.LeftButton)
        status_text = self.main_window.statusLabel.text()
        self.assertTrue(status_text in ['Status: Stopped', 'Status: Error stopping capture: Unsupported (offline or unsupported socket)'])

    @classmethod
    def tearDownClass(cls):
        cls.app.exit()

if __name__ == '__main__':
    unittest.main()
