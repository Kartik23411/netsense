import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import sniff
from src.analysis.ethernet_decoder import EthernetDecoder
from src.analysis.arp_analyzer import ARPAnalyzer
from src.analysis.ipv4_analyzer import IPv4Analyzer
from src.analysis.ipv6_analyzer import IPv6Analyzer
from src.analysis.icmp_analyzer import ICMPAnalyzer
from src.analysis.protocol_stats import ProtocolStatistics

# Initialize all analyzers
eth_decoder = EthernetDecoder()
arp_analyzer = ARPAnalyzer()
ipv4_analyzer = IPv4Analyzer()
ipv6_analyzer = IPv6Analyzer()
icmp_analyzer = ICMPAnalyzer()
stats = ProtocolStatistics()

def callback(packet):
    print(f"\n{'='*60}")
    
    # Layer 2 - Ethernet
    if packet.haslayer('Ether'):
        eth_info = eth_decoder.decode(packet)
        print(f"[L2] {eth_info['src_mac']} ({eth_info['src_vendor']}) → {eth_info['dst_mac']}")
        print(f"     Type: {eth_info['ether_type_name']}, Size: {eth_info['frame_size']} bytes")
        stats.update(eth_info)
        
        if eth_info['vlan']:
            print(f"     VLAN: ID={eth_info['vlan']['id']}, Priority={eth_info['vlan']['priority']}")
    
    # ARP
    if packet.haslayer('ARP'):
        arp_info = arp_analyzer.analyze(packet)
        print(f"[ARP] {arp_info['type']}: {arp_info['sender_ip']} is-at {arp_info['sender_mac']}")
        print(f"      Target: {arp_info['target_ip']}")
        stats.update(arp_info)
        
        if arp_info['alert']:
            alert = arp_info['alert']
            print(f"  SPOOFING DETECTED!")
            print(f"      IP {alert['ip']} changed from {alert['old_mac']} to {alert['new_mac']}")
    
    # IPv4
    if packet.haslayer('IP'):
        ipv4_info = ipv4_analyzer.analyze(packet)
        print(f"[IPv4] {ipv4_info['src_ip']} → {ipv4_info['dst_ip']}")
        print(f"       Protocol: {ipv4_info['protocol_name']}, TTL: {ipv4_info['ttl']}")
        print(f"       Header: {ipv4_info['header_size']} bytes, ID: {ipv4_info['identification']}")
        print(f"       Flags: DF={ipv4_info['flag_df']}, MF={ipv4_info['flag_mf']}")
        
        if ipv4_info['is_fragmented']:
            print(f"        FRAGMENTED! Offset: {ipv4_info['fragment_offset']}")
        
        stats.update(ipv4_info)
    
    # IPv6
    if packet.haslayer('IPv6'):
        ipv6_info = ipv6_analyzer.analyze(packet)
        print(f"[IPv6] {ipv6_info['src_ip']} → {ipv6_info['dst_ip']}")
        print(f"       Hop Limit: {ipv6_info['hop_limit']}, Payload: {ipv6_info['payload_length']} bytes")
        print(f"       Flow Label: {ipv6_info['flow_label']}, Traffic Class: {ipv6_info['traffic_class']}")
        stats.update(ipv6_info)
    
    # ICMP
    if packet.haslayer('ICMP'):
        icmp_info = icmp_analyzer.analyze(packet)
        print(f"[ICMP] Type: {icmp_info['type']}, Code: {icmp_info['code']}")
        
        if icmp_info['id'] is not None:
            print(f"       Ping ID: {icmp_info['id']}, Seq: {icmp_info['sequence']}")
        
        if icmp_info['rtt'] is not None:
            print(f"       ⚡ RTT: {icmp_info['rtt']*1000:.2f} ms")
        
        stats.update(icmp_info)

print(" Starting comprehensive packet analysis...\n")
print("Capturing 20 packets (try pinging something for ICMP!)")
print("Run: ping google.com in another terminal\n")

sniff(prn=callback, count=20, store=False)

# Show final statistics
print(f"\n{'='*60}")
print(" FINAL STATISTICS")
print(f"{'='*60}")

summary = stats.get_summary()

print(f"\n Total Packets: {summary['total_packets']}")
print(f" Total Bytes: {summary['total_bytes']:,}")

print(f"\n Ethernet Types:")
for eth_type, count in summary['ethernet'].items():
    print(f"   {eth_type}: {count}")

print(f"\n ARP:")
print(f"   Requests: {summary['arp']['requests']}")
print(f"   Replies: {summary['arp']['replies']}")

print(f"\n IPv4:")
print(f"   Total: {summary['ipv4']['total']}")
if summary['ipv4']['protocols']:
    print(f"   Protocols:")
    for proto, count in summary['ipv4']['protocols'].items():
        proto_name = ipv4_analyzer.get_protocol_name(proto)
        print(f"      {proto_name}: {count}")

print(f"\n IPv6:")
print(f"   Total: {summary['ipv6']['total']}")

print(f"\n📍 ICMP:")
print(f"   Total: {summary['icmp']['total']}")
if summary['icmp']['types']:
    print(f"   Types:")
    for icmp_type, count in summary['icmp']['types'].items():
        print(f"      {icmp_type}: {count}")

# Show ARP cache
print(f"\n ARP Cache ({len(arp_analyzer.arp_cache)} entries):")
for ip, info in list(arp_analyzer.arp_cache.items())[:10]:  # Show first 10
    print(f"   {ip:15s} → {info['mac']}")

# Show any spoofing alerts
if arp_analyzer.spoofing_alerts:
    print(f"\n  SPOOFING ALERTS ({len(arp_analyzer.spoofing_alerts)}):")
    for alert in arp_analyzer.spoofing_alerts:
        print(f"   {alert['ip']}: {alert['old_mac']} → {alert['new_mac']}")

print(f"\n{'='*60}")
print("Analysis complete!")