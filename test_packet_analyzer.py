# test_packet_analyzer.py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import unittest
from unittest.mock import patch, MagicMock
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw
from Nids import PacketAnalyzer

class TestPacketAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PacketAnalyzer()

    @patch.object(PacketAnalyzer, 'new_alert')
    def test_syn_flood_detection(self, mock_new_alert):
        packet = Ether()/IP(src='192.168.1.1')/TCP(flags='S')
        for _ in range(self.analyzer.syn_threshold + 1):
            self.analyzer.analyze(packet)
        mock_new_alert.assert_called_with('Potential SYN Flood Attack from 192.168.1.1')

    @patch.object(PacketAnalyzer, 'new_alert')
    def test_udp_flood_detection(self, mock_new_alert):
        packet = Ether()/IP(src='192.168.1.1')/UDP()
        for _ in range(self.analyzer.udp_threshold + 1):
            self.analyzer.analyze(packet)
        mock_new_alert.assert_called_with('Potential UDP Flood Attack from 192.168.1.1')

    @patch.object(PacketAnalyzer, 'new_alert')
    def test_icmp_flood_detection(self, mock_new_alert):
        packet = Ether()/IP(src='192.168.1.1')/ICMP(type=8)
        for _ in range(self.analyzer.icmp_threshold + 1):
            self.analyzer.analyze(packet)
        mock_new_alert.assert_called_with('Potential ICMP Flood Attack from 192.168.1.1')

    def test_non_ip_packet(self):
        packet = Ether()/Raw(load="Non-IP packet")
        self.analyzer.analyze(packet)
        self.assertEqual(len(self.analyzer.captured_packets), 1)

if __name__ == '__main__':
    unittest.main()
