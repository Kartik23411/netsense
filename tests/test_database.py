import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


from src.storage.database import NetSenseDB
import time

def test_db():

    print("------- Starting the test ------")

    db = NetSenseDB("test_db.db")
    print('db initialized')

    flow_id = db.get_flow_id(
        src_ip='192.068.0.100',
        dst_ip='0.0.0.0',
        src_port=54321,
        dst_port=53,
        protocol='IPv6'
    )

    test_pkt = [
        {
            'timestamp': time.time(),
            'src_mac': 'ac:dc:4d:3d',
            'dst_mac': 'da:et:dv:qd',
            'ether_type': 'IP',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'ip_protocol': 'TCP',
            'ttl': 43,
            'packet_size': 4,
            'interface': 'wlan',
            'src_port': 54321,
            'dst_port': 53,
            'tcp_flags': 'FA',
            'flow_id': flow_id,
        }
    ]

    for pkt in test_pkt:
        packet_id = db.insert_packet(pkt)
        print(f"✓ Inserted packet {packet_id}")

    packets = db.get_packets(limit=10)
    print(f"\n✓ Retrieved {len(packets)} packets")

    filtered = db.get_packets(filters={'protocol': 'TCP'})
    print(f"✓ Filtered packets: {len(filtered)}")
    
    # 5. Get flows
    flows = db.get_flows()
    print(f"✓ Retrieved {len(flows)} flows")
    
    # 6. Get statistics
    stats = db.get_statistics()
    print(f"\n=== Statistics ===")
    print(f"Total packets: {stats['total_packets']}")
    print(f"TCP: {stats['tcp_count']}, UDP: {stats['udp_count']}")
    
    db.close()
    print("\n✓ All tests passed!")


if __name__ == "__main__":
    test_db()