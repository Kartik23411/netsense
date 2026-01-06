from scapy.all import sniff, get_if_list
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.analysis.http_analyzer import HTTPAnalyzer

analyzer = HTTPAnalyzer()
packet_count = 0

def callback(packet):
    global packet_count
    packet_count += 1
    
    result = analyzer.analyze(packet)
    
    if result:
        if result['type'] == 'HTTP_REQUEST':
            print(f"\n[HTTP Request]")
            print(f"  {result['method']} {result['full_url']}")
            print(f"  User-Agent: {result['user_agent']}")
        
        elif result['type'] == 'HTTP_RESPONSE':
            print(f"\n[HTTP Response]")
            print(f"  Status: {result['status_code']} {result['status_text']}")
            print(f"  Content-Type: {result['content_type']}")
        
        elif result['type'] == 'TLS_HANDSHAKE':
            print(f"\n[HTTPS - {result['handshake_type']}]")
            print(f"  {result['src_ip']}:{result['src_port']} → {result['dst_ip']}:{result['dst_port']}")
            print(f"  Version: {result['tls_version']}")

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
print(f"HTTP Requests: {stats['http_requests']}")
print(f"HTTP Responses: {stats['http_responses']}")
print(f"HTTPS Connections: {stats['https_connections']}")
print(f"TLS Handshakes: {stats['tls_handshakes']}")