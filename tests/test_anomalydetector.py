import sys
import os
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.intelligence.anomaly_detector import AnomalyDetector
from rich.console import Console

console = Console()
detector = AnomalyDetector()

console.print("[bold cyan] Testing Anomaly Detector[/bold cyan]\n")

# Phase 1: Collect baseline (normal traffic)
console.print("[yellow]Phase 1: Collecting baseline (normal traffic)...[/yellow]")

normal_packets = [
    {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'dst_port': 443, 'packet_size': 1200, 'protocol_name': 'TCP', 'ttl': 64},
    {'src_ip': '192.168.1.100', 'dst_ip': '1.1.1.1', 'dst_port': 443, 'packet_size': 1150, 'protocol_name': 'TCP', 'ttl': 64},
    {'src_ip': '192.168.1.100', 'dst_ip': '8.8.4.4', 'dst_port': 53, 'packet_size': 60, 'protocol_name': 'UDP', 'ttl': 64},
    {'src_ip': '192.168.1.100', 'dst_ip': '1.1.1.1', 'dst_port': 80, 'packet_size': 800, 'protocol_name': 'TCP', 'ttl': 64},
    {'src_ip': '192.168.1.101', 'dst_ip': '8.8.8.8', 'dst_port': 443, 'packet_size': 1300, 'protocol_name': 'TCP', 'ttl': 63},
    {'src_ip': '192.168.1.102', 'dst_ip': '1.1.1.1', 'dst_port': 443, 'packet_size': 1100, 'protocol_name': 'TCP', 'ttl': 64},
] * 40  # 240 samples

for pkt in normal_packets:
    detector.collect_baseline(pkt)

console.print(f"[green]✓[/green] Collected {len(detector.baseline_features)} baseline samples\n")

# Phase 2: Train model
console.print("[yellow]Phase 2: Training Isolation Forest...[/yellow]")
success, message = detector.train_model()
if success:
    console.print(f"[green]✓[/green] {message}\n")
else:
    console.print(f"[red]✗[/red] {message}\n")

# Phase 3: Test with normal traffic
console.print("[yellow]Phase 3: Testing with normal traffic...[/yellow]")
test_normal = {
    'src_ip': '192.168.1.100',
    'dst_ip': '8.8.8.8',
    'dst_port': 443,
    'packet_size': 1100,
    'protocol_name': 'TCP',
    'ttl': 64
}

result = detector.predict_anomaly(test_normal)
if result:
    if result['is_anomaly']:
        console.print(f"[red]✗[/red] False positive! Normal traffic flagged as anomaly")
    else:
        console.print(f"[green]✓[/green] Normal traffic correctly identified (confidence: {result['confidence']:.1%})")
console.print()

# Phase 4: Test with anomalies
console.print("[yellow]Phase 4: Testing with anomalous traffic...[/yellow]")

# Test 1: Port scan
console.print("[bold]Test 1: Port Scan Detection[/bold]")
for port in range(20, 35):
    pkt = {
        'src_ip': '192.168.1.200',
        'dst_ip': '192.168.1.100',
        'dst_port': port,
        'packet_size': 60,
        'protocol_name': 'TCP',
        'ttl': 64
    }
    alerts = detector.analyze(pkt)
    if alerts:
        for alert in alerts:
            severity_color = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'cyan'}
            color = severity_color.get(alert.get('severity', 'MEDIUM'), 'yellow')
            console.print(f"[{color}]🚨 {alert['type']}:[/{color}] {alert['description']}")
        break

# Test 2: Unusual packet size (ML detection)
console.print("\n[bold]Test 2: ML Anomaly Detection (Large Packet)[/bold]")
huge_packet = {
    'src_ip': '192.168.1.100',
    'dst_ip': '8.8.8.8',
    'dst_port': 443,
    'packet_size': 50000,
    'protocol_name': 'TCP',
    'ttl': 64
}

result = detector.predict_anomaly(huge_packet)
if result:
    if result['is_anomaly']:
        console.print(f"[red]🚨 Anomaly detected![/red]")
        console.print(f"  Confidence: {result['confidence']:.1%}")
        console.print(f"  Score: {result['anomaly_score']:.3f}")
    else:
        console.print(f"[green]✓[/green] Large packet accepted (confidence: {result['confidence']:.1%})")

# Test 3: DDoS simulation
console.print("\n[bold]Test 3: DDoS Detection[/bold]")
# Simulate high rate
for i in range(150):
    detector.calculate_packet_rate('10.0.0.100')

pkt = {
    'src_ip': '10.0.0.100',
    'dst_ip': '192.168.1.1',
    'dst_port': 80,
    'packet_size': 64,
    'protocol_name': 'TCP',
    'ttl': 64
}

alerts = detector.analyze(pkt)
if alerts:
    for alert in alerts:
        severity_color = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'cyan'}
        color = severity_color.get(alert.get('severity', 'MEDIUM'), 'yellow')
        console.print(f"[{color}]🚨 {alert['type']}:[/{color}] {alert['description']}")

# Show statistics
console.print("\n[bold] Detector Statistics:[/bold]")
stats = detector.get_statistics()
for key, value in stats.items():
    console.print(f"  {key}: {value}")