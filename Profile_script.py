# profile_script.py
import cProfile
from scapy.all import IP, TCP
from nids import PacketAnalyzer

def profile_analysis():
    analyzer = PacketAnalyzer()
    # Simulate high traffic volume
    for _ in range(10000):
        packet = IP(src='192.168.1.1') / TCP(flags="S")
        analyzer.analyze(packet)

if __name__ == '__main__':
    cProfile.run('profile_analysis()')
