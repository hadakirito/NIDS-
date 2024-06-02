import sys
import time
import os
import signal
from collections import defaultdict
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QComboBox, QTextEdit, QFileDialog, QLineEdit
import psutil
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, DNS, Raw, wrpcap
import smtplib
from email.mime.text import MIMEText
import logging

# Configure logging
log_file = 'Logs.log'
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PacketAnalyzer(QObject):
    new_packet = pyqtSignal(str)
    alert_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.captured_packets = []
        self.syn_count = defaultdict(lambda: [0, time.time()])
        self.udp_count = defaultdict(lambda: [0, time.time()])
        self.icmp_count = defaultdict(lambda: [0, time.time()])
        self.time_window = 1

        self.syn_threshold = 100
        self.udp_threshold = 100
        self.icmp_threshold = 100

        self.smtp_server = 'smtp.gmail.com'
        self.smtp_port = 465
        self.smtp_username = os.getenv('nids.project07@gmail.com', '"')
        self.smtp_password = os.getenv('nlxaabngeuronnks', '"')
        self.alert_recipient = 'akhiata055@gmail.com'

    def send_alert(self, subject, message):
        try:
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = self.smtp_username
            msg['To'] = self.alert_recipient

            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.smtp_username, self.alert_recipient, msg.as_string())
            logging.info(f"Alert sent: {subject}")
        except Exception as e:
            logging.error(f"Failed to send alert: {e}")

    def new_alert(self, alert):
        logging.info(f"Generating new alert: {alert}")
        self.send_alert('NIDS Alert', alert)
        self.alert_signal.emit(alert)

    def analyze(self, packet):
        try:
            self.captured_packets.append(packet)
            packet_summary = str(packet.summary())
            self.new_packet.emit(packet_summary)
            current_time = time.time()

            if not packet.haslayer(IP):
                logging.debug("Packet does not have IP layer")
                return

            src_ip = packet[IP].src
            logging.debug(f"Analyzing packet from {src_ip}")

            if packet.haslayer(TCP):
                self.handle_tcp_packet(packet, src_ip, current_time)
            elif packet.haslayer(UDP):
                self.handle_udp_packet(packet, src_ip, current_time)
            elif packet.haslayer(ICMP):
                self.handle_icmp_packet(packet, src_ip, current_time)
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")

    def handle_tcp_packet(self, packet, src_ip, current_time):
        if packet[TCP].flags == "S":
            self.syn_count[src_ip][0] += 1
            logging.debug(f"SYN count for {src_ip}: {self.syn_count[src_ip][0]}")
            if self.syn_count[src_ip][0] > self.syn_threshold:
                self.new_alert(f"Potential SYN Flood Attack from {src_ip}")
            self.reset_count(self.syn_count, current_time)

    def handle_udp_packet(self, packet, src_ip, current_time):
        self.udp_count[src_ip][0] += 1
        logging.debug(f"UDP count for {src_ip}: {self.udp_count[src_ip][0]}")
        if self.udp_count[src_ip][0] > self.udp_threshold:
            self.new_alert(f"Potential UDP Flood Attack from {src_ip}")
        self.reset_count(self.udp_count, current_time)
        
    def handle_icmp_packet(self, packet, src_ip, current_time):
        if packet[ICMP].type == 8:
            self.icmp_count[src_ip][0] += 1
            logging.debug(f"ICMP count for {src_ip}: {self.icmp_count[src_ip][0]}")
            if self.icmp_count[src_ip][0] > self.icmp_threshold:
                self.new_alert(f"Potential ICMP Flood Attack from {src_ip}")
            self.reset_count(self.icmp_count, current_time)

    def reset_count(self, count_dict, current_time):
        for ip in list(count_dict.keys()):
            if current_time - count_dict[ip][1] > self.time_window:
                logging.debug(f"Resetting count for {ip}")
                del count_dict[ip]

class NIDSMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.packet_analyzer = PacketAnalyzer()
        self.sniffer = None
        self.initUI()

        self.packet_analyzer.new_packet.connect(self.updatePacketDisplay)
        self.packet_analyzer.alert_signal.connect(self.updateIntrusionDisplay)

        # Signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        logging.info("Signal handler called with signal: {}".format(sig))
        self.stopCapturing()
        QApplication.quit()

    def initUI(self):
        self.setWindowTitle('Network Intrusion Detection System')
        self.setGeometry(100, 100, 800, 600)

        self.centralWidget = QWidget(self)
        self.setCentralWidget(self.centralWidget)

        layout = QVBoxLayout(self.centralWidget)

        self.interfaceLabel = QLabel('Select Network Interface:', self)
        layout.addWidget(self.interfaceLabel)

        self.interfaceComboBox = QComboBox(self)
        self.populateInterfaces()
        layout.addWidget(self.interfaceComboBox)

        buttonLayout = QHBoxLayout()
        self.startButton = QPushButton('Start Capturing', self)
        buttonLayout.addWidget(self.startButton)

        self.stopButton = QPushButton('Stop Capturing', self)
        buttonLayout.addWidget(self.stopButton)

        self.clearButton = QPushButton('Clear', self)
        buttonLayout.addWidget(self.clearButton)

        self.saveButton = QPushButton('Save Captured Packets', self)
        buttonLayout.addWidget(self.saveButton)

        self.checkLogsButton = QPushButton('Check Logs', self)
        buttonLayout.addWidget(self.checkLogsButton)

        layout.addLayout(buttonLayout)

        displayLayout = QHBoxLayout()

        packetDisplayLayout = QVBoxLayout()
        self.packetDisplay = QTextEdit(self)
        self.packetDisplay.setReadOnly(True)
        packetDisplayLayout.addWidget(QLabel('All Captured Packets', self))
        packetDisplayLayout.addWidget(self.packetDisplay)

        intrusionDisplayLayout = QVBoxLayout()
        self.intrusionDisplay = QTextEdit(self)
        self.intrusionDisplay.setReadOnly(True)
        intrusionDisplayLayout.addWidget(QLabel('Intrusion Alerts', self))
        intrusionDisplayLayout.addWidget(self.intrusionDisplay)

        displayLayout.addLayout(packetDisplayLayout)
        displayLayout.addLayout(intrusionDisplayLayout)

        layout.addLayout(displayLayout)

        self.statusLabel = QLabel('Status: Idle', self)
        layout.addWidget(self.statusLabel)

        self.startButton.clicked.connect(self.startCapturing)
        self.stopButton.clicked.connect(self.stopCapturing)
        self.clearButton.clicked.connect(self.clearDisplays)
        self.saveButton.clicked.connect(self.saveCapturedPackets)
        self.checkLogsButton.clicked.connect(self.checkLogs)

        self.addThresholdInputs(layout)

    def populateInterfaces(self):
        interfaces = self.getFilteredInterfaces()
        self.interfaceComboBox.addItems(interfaces)

    def getFilteredInterfaces(self):
        interfaces = psutil.net_if_addrs()
        if sys.platform == "win32":
            filtered_interfaces = [iface for iface in interfaces.keys() if "Ethernet" in iface or "Wi-Fi" in iface]
        elif sys.platform.startswith("linux"):
            filtered_interfaces = [iface for iface in interfaces.keys() if iface.startswith("eth") or iface.startswith("wlan") or iface.startswith("en") or iface.startswith("wl")]
        else:
            filtered_interfaces = list(interfaces.keys())
        logging.debug(f"Filtered interfaces: {filtered_interfaces}")
        return filtered_interfaces

    def startCapturing(self):
        try:
            self.statusLabel.setText('Status: Capturing...')
            iface = self.interfaceComboBox.currentText()
            logging.debug(f"Starting capture on interface: {iface}")
            self.sniffer = AsyncSniffer(iface=iface, prn=self.packet_analyzer.analyze)
            self.sniffer.start()
        except Exception as e:
            self.statusLabel.setText(f'Status: Error starting capture: {e}')
            logging.error(f"Error starting capture: {e}")

    def stopCapturing(self):
        try:
           if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.statusLabel.setText('Status: Stopped')
        except Exception as e:
            self.statusLabel.setText(f'Status: Error stopping capture: {e}')
            logging.error(f"Error stopping capture: {e}")
    
    def updatePacketDisplay(self, packet_summary):
        self.packetDisplay.append(packet_summary)

    def updateIntrusionDisplay(self, alert):
        logging.info(f"Updating intrusion display with alert: {alert}")
        self.intrusionDisplay.append(alert)

    def clearDisplays(self):
        self.packetDisplay.clear()
        self.intrusionDisplay.clear()
        self.packet_analyzer.captured_packets.clear()

    def saveCapturedPackets(self):
        try:
            options = QFileDialog.Options()
            filePath, _ = QFileDialog.getSaveFileName(self, "Save Captured Packets", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
            if filePath:
                wrpcap(filePath, self.packet_analyzer.captured_packets)
                self.statusLabel.setText(f'Status: Packets saved to {filePath}')
                logging.info(f"Packets saved to {filePath}")
        except Exception as e:
            self.statusLabel.setText(f'Status: Error saving packets: {e}')
            logging.error(f"Error saving packets: {e}")

    def saveThresholds(self):
        try:
            self.packet_analyzer.syn_threshold = int(self.synThresholdInput.text())
            self.packet_analyzer.udp_threshold = int(self.udpThresholdInput.text())
            self.packet_analyzer.icmp_threshold = int(self.icmpThresholdInput.text())
            self.statusLabel.setText('Status: Thresholds updated')
        except ValueError:
            self.statusLabel.setText('Status: Invalid threshold value')
            logging.error("Invalid threshold value entered")

    def checkLogs(self):
        if os.path.exists(log_file):
            if sys.platform == "win32":
                os.system(f'notepad.exe {log_file}')
            else:
                os.system(f'xdg-open {log_file}')
        else:
            self.statusLabel.setText('Log file does not exist')

    def addThresholdInputs(self, layout):
        threshold_labels = [
            ('SYN Threshold:', 'syn_threshold'),
            ('UDP Threshold:', 'udp_threshold'),
            ('ICMP Threshold:', 'icmp_threshold'),
        ]
        for label_text, attr in threshold_labels:
            label = QLabel(label_text, self)
            input_field = QLineEdit(str(getattr(self.packet_analyzer, attr)), self)
            layout.addWidget(label)
            layout.addWidget(input_field)
            setattr(self, f"{attr}Input", input_field)
        self.saveThresholdsButton = QPushButton('Save Thresholds', self)
        layout.addWidget(self.saveThresholdsButton)
        self.saveThresholdsButton.clicked.connect(self.saveThresholds)

if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        mainWindow = NIDSMainWindow()
        mainWindow.show()
        sys.exit(app.exec_())
    except Exception as e:
        logging.error(f"Exception in main: {e}")
