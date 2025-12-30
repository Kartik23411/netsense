from scapy.all import sniff
import sys
sys.path.append('..')  # Add parent directory to path
from src.storage.database import NetSenseDB

# mappings 
ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Initialize database
db = NetSenseDB('test_db.db')

def packet_callback(packet):
    print(f"\n--- Packet {packet_callback.count} ---")
    
    # Initialize packet data dictionary
    packet_data = {
        'timestamp': float(packet.time),
        'src_mac': None,
        'dst_mac': None,
        'ether_type': None,
        'src_ip': None,
        'dst_ip': None,
        'ip_protocol': None,
        'ttl': None,
        'src_port': None,
        'dst_port': None,
        'tcp_flags': None,
        'packet_size': len(packet),
        'interface': 'default',
        'flow_id': None
    }
    
    try:
        # Ethernet
        if packet.haslayer('Ether'):
            print("[Ethernet]")
            packet_data['src_mac'] = packet['Ether'].src
            packet_data['dst_mac'] = packet['Ether'].dst
            packet_data['ether_type'] = ETHER_TYPES.get(packet['Ether'].type, f"Unknown")
            
            print(f"\t Source MAC: {packet_data['src_mac']}")
            print(f"\t Dest MAC: {packet_data['dst_mac']}")
            print(f"\t Type: {packet_data['ether_type']}")

        # ARP
        if packet.haslayer("ARP"):
            print("[ARP]")
            print(f"\t Source IP: {packet['ARP'].psrc}")
            print(f"\t Dest IP: {packet['ARP'].pdst}")
            packet_data['ip_protocol'] = 'ARP'
            packet_callback.arp_count += 1

        # IP
        elif packet.haslayer("IP"):
            print("[IP]")
            packet_data['src_ip'] = packet['IP'].src
            packet_data['dst_ip'] = packet['IP'].dst
            packet_data['ttl'] = packet['IP'].ttl
            
            proto = packet['IP'].proto
            proto_name = IP_PROTOCOLS.get(proto, f"Other")
            packet_data['ip_protocol'] = proto_name
            
            print(f"\t Source: {packet_data['src_ip']}")
            print(f"\t Dest: {packet_data['dst_ip']}")
            print(f"\t Protocol: {proto_name}")
            print(f"\t TTL: {packet_data['ttl']}")
            
            # TCP
            if packet.haslayer("TCP"):
                print("[TCP]")
                packet_data['src_port'] = packet['TCP'].sport
                packet_data['dst_port'] = packet['TCP'].dport
                packet_data['tcp_flags'] = str(packet['TCP'].flags)
                
                print(f"\t Source Port: {packet_data['src_port']}")
                print(f"\t Dest Port: {packet_data['dst_port']}")
                print(f"\t Flags: {packet_data['tcp_flags']}")
                
                # Get or create flow
                flow_id = db.get_flow_id(
                    packet_data['src_ip'],
                    packet_data['dst_ip'],
                    packet_data['src_port'],
                    packet_data['dst_port'],
                    'TCP'
                )
                packet_data['flow_id'] = flow_id
                
                # Update flow statistics
                db.update_flow(flow_id, packet_data)
                
                packet_callback.tcp_count += 1
                
            # UDP
            elif packet.haslayer("UDP"):
                print("[UDP]")
                packet_data['src_port'] = packet['UDP'].sport
                packet_data['dst_port'] = packet['UDP'].dport
                
                print(f"\t Source Port: {packet_data['src_port']}")
                print(f"\t Dest Port: {packet_data['dst_port']}")
                print(f"\t Length: {packet['UDP'].len}")
                
                # DNS
                if packet.haslayer("DNS"):
                    print("[DNS]")
                    if packet['DNS'].qd:
                        query_name = packet['DNS'].qd.qname.decode('utf-8', errors='ignore')
                        print(f"\t Query: {query_name}")
                    packet_callback.dns_count += 1
                else:
                    packet_callback.udp_count += 1
                
                # Get or create flow
                flow_id = db.get_flow_id(
                    packet_data['src_ip'],
                    packet_data['dst_ip'],
                    packet_data['src_port'],
                    packet_data['dst_port'],
                    'UDP'
                )
                packet_data['flow_id'] = flow_id
                db.update_flow(flow_id, packet_data)
                
            # ICMP
            elif packet.haslayer("ICMP"):
                print("[ICMP]")
                print(f"\t Type: {packet['ICMP'].type}")
                print(f"\t Code: {packet['ICMP'].code}")
                packet_callback.icmp_count += 1
            else:
                packet_callback.other_count += 1
        else:
            packet_callback.other_count += 1
        
        
        packet_id = db.insert_packet(packet_data)
        print(f"Stored in database with ID: {packet_id}")
            
    except Exception as e:
        print(f"Error processing packet: {e}")
        import traceback
        traceback.print_exc()
    
    packet_callback.count += 1


# counters
packet_callback.count = 1
packet_callback.tcp_count = 0
packet_callback.udp_count = 0
packet_callback.dns_count = 0
packet_callback.arp_count = 0
packet_callback.icmp_count = 0
packet_callback.other_count = 0

def print_statistics():
    total = packet_callback.count - 1
    if total == 0:
        return
    
    print("\n========== Capture Statistics ==========")
    print(f"Total Packets: {total}")
    
    stats = [
        ("TCP", packet_callback.tcp_count),
        ("UDP", packet_callback.udp_count),
        ("DNS", packet_callback.dns_count),
        ("ARP", packet_callback.arp_count),
        ("ICMP", packet_callback.icmp_count),
        ("Other", packet_callback.other_count),
    ]
    
    for name, count in stats:
        percentage = (count / total * 100) if total > 0 else 0
        print(f"{name}: {count} ({percentage:.1f}%)")
    print("=" * 40)
    
    # Get database statistics
    print("\n========== Database Statistics ==========")
    db_stats = db.get_statistics()
    print(f"Total Packets in DB: {db_stats['total_packets']}")
    print(f"Total Bytes: {db_stats['total_bytes']}")
    print(f"TCP Packets: {db_stats['tcp_count']}")
    print(f"UDP Packets: {db_stats['udp_count']}")
    print(f"Active Flows: {db_stats['active_flows']}")
    print("\nTop Source IPs:")
    for ip_stat in db_stats['top_source_ips']:
        print(f"  {ip_stat['src_ip']}: {ip_stat['packet_count']} packets")
    print("=" * 40)

def main():
    print("Starting packet capture... (sniffing 10 packets)")
    print("Packets will be stored in database\n")
    
    try:
        sniff(prn=packet_callback, count=10, store=False)
        print_statistics()
        
        # Show some flows
        print("\n========== Flows ==========")
        flows = db.get_flows(limit=5)
        for flow in flows:
            print(f"\nFlow {flow['id']}:")
            print(f"  {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']} ({flow['protocol']})")
            print(f"  Packets: {flow['packet_count']}, Bytes: {flow['total_bytes']}")
            if flow['duration']:
                print(f"  Duration: {flow['duration']:.2f}s")
        
        print("\n✓ Packet capture complete!")
        print(f"Database: netsense.db")
        
    except PermissionError:
        print("Error: This script requires administrator privileges.")
        print("Please run with: sudo python advance_sniffer.py")
    except KeyboardInterrupt:
        print("\n\nPacket capture interrupted by user")
        print_statistics()
    finally:
        db.close()


if __name__ == "__main__":
    main()