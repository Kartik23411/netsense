import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import sniff
from src.analysis.ethernet_decoder import EthernetDecoder

decoder = EthernetDecoder()

def test_callback(packet):
    if packet.haslayer('Ether'):
        eth_info = decoder.decode(packet)
        print(f"\n=== Ethernet Frame ===")
        print(f"Src: {eth_info['src_mac']} ({eth_info['src_type']}) Vendor: {eth_info['src_vendor']}")
        print(f"Dst: {eth_info['dst_mac']} ({eth_info['dst_type']}) Vendor: {eth_info['dst_vendor']}")
        print(f"Type: {eth_info['ether_type_name']}")
        if eth_info.get('vlan'):
            print(f"VLAN: ID={eth_info['vlan']['id']}, Priority={eth_info['vlan']['priority']}")

sniff(prn=test_callback, count=5)