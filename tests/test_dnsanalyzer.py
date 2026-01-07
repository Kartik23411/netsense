from scapy.all import sniff, get_if_list
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.analysis.dns_analyzer import DNSAnalyzer

analyzer = DNSAnalyzer()
packet_count = 0

def callback(packet):
    global packet_count
    packet_count += 1
    
    result = analyzer.analyze(packet)
    
    if result:
        if result['type'] == 'DNS_RESPONSE':
            status = result.get('response_status', 'NOERROR')
            print(f"\n[DNS Response - {status}]")  
            print(f"  transaction_id: {result['transaction_id']}")
            if result['answers']:
                print(f"  Answers: {result['answers']}")
            else:
                print(f"  No answers (domain may not exist)")
            print(f"  {result['src_ip']} → {result['dst_ip']}")
        
        elif result['type'] == 'DNS_QUERY':
            print(f"\n[ dns query]")
            print(f"  {result['transaction_id']} {result['query_name']}")
            print(f"  src: {result['src_ip']} dst: {result['dst_ip']}")
        

# Show available interfaces
print("Available network interfaces:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"  {i}: {iface}")

# Auto-select the first non-loopback interface
iface = None
for interface in interfaces:
    if interface not in ['lo', 'lo0']:
        iface = interface
        break

if not iface:
    print("\nERROR: No network interface found!")
    sys.exit(1)

print(f"\nSniffing on interface: {iface}")
print("Waiting for real HTTP/HTTPS traffic...")
print("(Make sure other devices/browsers on your network are making HTTP/HTTPS requests)\n")

try:
    sniff(iface=iface, prn=callback, store=False)
except PermissionError:
    print("ERROR: Need root privileges!")
    print("Run with: sudo python tests/test_httpanalyzer.py")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n\nStopped by user")
except Exception as e:
    print(f"Error: {e}")

print(f"\n=== Statistics ===")
print(f"Total packets processed: {packet_count}")
stats = analyzer.get_statistics()
print(f"Total queries: {stats['total_queries']}")
print(f"Resolved queries: {stats['resolved_queries']}")
print(f"Pending queries: {stats['pending_queries']}")
print(f"Avg resoution time: {stats['avg_resolution_time']}")
print(f"Top Domains: {stats['top_domains']}")

