import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import sniff
from src.analysis.ethernet_decoder import EthernetDecoder
from src.analysis.arp_analyzer import ARPAnalyzer
from src.analysis.ipv4_analyzer import IPv4Analyzer

eth_decoder = EthernetDecoder()
arp_analyzer = ARPAnalyzer()
ipv4_analyzer = IPv4Analyzer()

def callback(packet):
    # Layer 2
    if packet.haslayer('Ether'):
        eth_info = eth_decoder.decode(packet)
        print(f"[L2] {eth_info['src_mac']} → {eth_info['dst_mac']}")
    
    # ARP
    if packet.haslayer('ARP'):
        arp_info = arp_analyzer.analyze(packet)
        print(f"[ARP] {arp_info['type']}: {arp_info['sender_ip']} is {arp_info['sender_mac']}")
        if arp_info['alert']:
            print(f"⚠️  {arp_info['alert']}")
    
    # # IPv4
    if packet.haslayer('IP'):
        ipv4_info = ipv4_analyzer.analyze(packet)
        print(f"[IPv4] {ipv4_info['src_ip']} → {ipv4_info['dst_ip']} TTL={ipv4_info['ttl']}")

sniff(prn=callback, count=10)