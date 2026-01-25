import sys
from pathlib import Path
import time
import json
from collections import defaultdict
import gc

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import PcapReader, TCP, IP
from src.storage.database import NetSenseDB
from src.intelligence.ml_detector import MLDetector
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()

class MLDetectionTester:
    def __init__(self, pcap_path, db_path='test_ml.db', chunk_size=1000):
        self.pcap_path = Path(pcap_path)
        self.chunk_size = chunk_size
        
        # Initialize components
        console.print(f"[cyan]Initializing test environment...[/cyan]")
        self.db = NetSenseDB(db_path)
        self.ml_detector = MLDetector()
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'flows_created': 0,
            'flows_analyzed': 0,
            'attacks_detected': defaultdict(int),
            'total_alerts': 0,
            'processing_time': 0,
            'flow_labels': {},  # For CICIDS labeled data
        }
        
        # Flow tracking
        self.analyzed_flows = set()
    
    def load_cicids_labels(self, csv_path):
        """
        Load CICIDS CSV labels to verify detection accuracy
        Optional: Use if you have the corresponding CSV file
        """
        import pandas as pd
        
        console.print(f"[cyan]Loading ground truth labels from CSV...[/cyan]")
        
        try:
            df = pd.read_csv(csv_path)
            
            # Create flow key from CSV
            for _, row in df.iterrows():
                flow_key = (
                    row.get(' Source IP', row.get('Source IP')),
                    row.get(' Destination IP', row.get('Destination IP')),
                    row.get(' Source Port', row.get('Source Port')),
                    row.get(' Destination Port', row.get('Destination Port')),
                )
                label = row.get(' Label', row.get('Label', 'BENIGN'))
                self.stats['flow_labels'][flow_key] = label
            
            console.print(f"[green]Loaded {len(self.stats['flow_labels'])} flow labels[/green]")
            
        except Exception as e:
            console.print(f"[yellow]    Could not load CSV labels: {e}[/yellow]")
            console.print("[yellow]   Continuing without ground truth verification[/yellow]")
    
    def process_pcap_chunked(self):
        """
        Process large PCAP file in chunks to avoid memory issues
        """
        console.print(f"\n[bold cyan]Processing PCAP: {self.pcap_path.name}[/bold cyan]")
        
        # Get file size
        file_size = self.pcap_path.stat().st_size
        file_size_mb = file_size / (1024 * 1024)
        console.print(f"File size: {file_size_mb:.2f} MB")
        
        start_time = time.time()
        
        # Use PcapReader for streaming (doesn't load entire file)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task(
                f"[cyan]Processing packets...",
                total=None  # Unknown total
            )
            
            try:
                with PcapReader(str(self.pcap_path)) as pcap:
                    chunk = []
                    
                    for packet in pcap:
                        chunk.append(packet)
                        
                        # Process in chunks
                        if len(chunk) >= self.chunk_size:
                            self._process_chunk(chunk)
                            chunk = []
                            
                            # Update progress
                            progress.update(
                                task,
                                description=f"[cyan]Processed {self.stats['packets_processed']:,} packets | "
                                           f"{self.stats['flows_created']} flows | "
                                           f"{self.stats['total_alerts']} alerts"
                            )
                    
                    # Process remaining packets
                    if chunk:
                        self._process_chunk(chunk)
                
            except Exception as e:
                console.print(f"[red]❌ Error processing PCAP: {e}[/red]")
                import traceback
                traceback.print_exc()
        
        self.stats['processing_time'] = time.time() - start_time
        
        # Final flow analysis (for flows that didn't reach threshold)
        self._analyze_remaining_flows()
    
    def _process_chunk(self, packets):
        """Process a chunk of packets"""
        for packet in packets:
            self._process_packet(packet)
        gc.collect()
    
    def _process_packet(self, packet):
        """Process single packet"""
        self.stats['packets_processed'] += 1
        
        # Only process IP packets
        if not packet.haslayer(IP):
            return
        
        # Extract packet data
        packet_data = self._extract_packet_data(packet)
        
        if not packet_data:
            return
        
        # Get or create flow
        flow_id = self.db.get_flow_id(
            packet_data['src_ip'],
            packet_data['dst_ip'],
            packet_data.get('src_port', 0),
            packet_data.get('dst_port', 0),
            packet_data.get('protocol', 'IP')
        )
        
        # Track new flows
        if flow_id not in self.analyzed_flows:
            self.stats['flows_created'] += 1
        
        # Update flow with packet
        try:
            self.db.update_flow(flow_id, packet_data, float(packet.time))
        except Exception as e:
            console.print(f"[yellow]  Flow update error: {e}[/yellow]")
            return
        
        # Check if flow ready for ML analysis
        if self._should_analyze_flow(flow_id):
            self._analyze_flow(flow_id)
    
    def _extract_packet_data(self, packet):
        """Extract packet information"""
        try:
            ip = packet[IP]
            
            data = {
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'packet_size': len(packet),
                'protocol': 'IP',
                'ttl': ip.ttl,
            }
            
            # TCP info
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                data.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'protocol': 'TCP',
                    'tcp_flags': str(tcp.flags),
                    'tcp_window': tcp.window,
                })
            
            return data
            
        except Exception as e:
            return None
    
    def _should_analyze_flow(self, flow_id):
        """Decide if flow should be analyzed"""
        if flow_id in self.analyzed_flows:
            return False
        
        flow = self.db.get_flow_by_id(flow_id)
        
        # Analyze when:
        # 1. Flow has at least 10 packets
        # 2. Flow has ended (has end_time)
        return (
            flow['packet_count'] >= 10 or
            flow['end_time'] is not None
        )
    
    def _analyze_flow(self, flow_id):
        """Run ML detection on flow"""
        self.analyzed_flows.add(flow_id)
        self.stats['flows_analyzed'] += 1
        
        try:
            # Get ML features
            features = self.db.get_ml_features(flow_id)
            
            # Run ML detection
            alerts = self.ml_detector.analyze_flow(features)
            
            if alerts:
                self.stats['total_alerts'] += len(alerts)
                
                for alert in alerts:
                    self.stats['attacks_detected'][alert['attack_type']] += 1
                    
                    # Store alert
                    flow = self.db.get_flow_by_id(flow_id)
                    self.db.insert_alert({
                        'timestamp': flow['start_time'],
                        'severity': alert['severity'],
                        'alert_type': alert['attack_type'],
                        'description': f"{alert['type']} (confidence: {alert['confidence']:.0%})",
                        'src_ip': flow['src_ip'],
                        'dst_ip': flow['dst_ip'],
                        'related_flow_id': flow_id
                    })
                    
                    # Verify against ground truth if available
                    self._verify_detection(flow, alert)
        
        except Exception as e:
            console.print(f"[red]❌ ML analysis error for flow {flow_id}: {e}[/red]")
    
    def _analyze_remaining_flows(self):
        """Analyze flows that didn't reach threshold"""
        console.print(f"\n[cyan]Analyzing remaining flows...[/cyan]")
        
        # Get all flows not yet analyzed
        all_flows = self.db.get_flows(limit=10000)
        
        remaining = [f for f in all_flows if f['id'] not in self.analyzed_flows]
        
        if remaining:
            console.print(f"Found {len(remaining)} flows to analyze")
            
            for flow in remaining:
                if flow['packet_count'] >= 5:  # Lower threshold for remaining
                    self._analyze_flow(flow['id'])
    
    def _verify_detection(self, flow, alert):
        """Verify detection against ground truth"""
        if not self.stats['flow_labels']:
            return
        
        flow_key = (
            flow['src_ip'],
            flow['dst_ip'],
            flow['src_port'],
            flow['dst_port']
        )
        
        true_label = self.stats['flow_labels'].get(flow_key, 'UNKNOWN')
        
        # Map our attack types to CICIDS labels
        attack_map = {
            'portscan': 'PortScan',
            'ddos': 'DDoS',
            'dos_hulk': 'DoS Hulk',
            'dos_slowhttp': 'DoS Slowhttp',
            'dos_slowloris': 'DoS slowloris',
            'dos_goldeneye': 'DoS GoldenEye'
        }
        
        predicted = attack_map.get(alert['attack_type'], alert['attack_type'])
        
        if true_label != 'UNKNOWN':
            if predicted in true_label or true_label in predicted:
                console.print(f"[green] Correct: {predicted} == {true_label}[/green]")
            else:
                console.print(f"[yellow]  Mismatch: Predicted {predicted}, True {true_label}[/yellow]")
    
    def print_results(self):
        """Print test results"""
        console.print("\n" + "="*70)
        console.print("[bold cyan]🧪 TEST RESULTS[/bold cyan]")
        console.print("="*70)
        
        # Summary table
        summary = Table(title="Summary Statistics")
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="yellow", justify="right")
        
        summary.add_row("Packets Processed", f"{self.stats['packets_processed']:,}")
        summary.add_row("Flows Created", f"{self.stats['flows_created']:,}")
        summary.add_row("Flows Analyzed", f"{self.stats['flows_analyzed']:,}")
        summary.add_row("Total Alerts", f"{self.stats['total_alerts']:,}")
        summary.add_row("Processing Time", f"{self.stats['processing_time']:.2f}s")
        summary.add_row("Packets/sec", f"{self.stats['packets_processed']/self.stats['processing_time']:.0f}")
        
        console.print(summary)
        
        # Attacks detected
        if self.stats['attacks_detected']:
            console.print("\n[bold]Attacks Detected:[/bold]")
            
            attacks_table = Table()
            attacks_table.add_column("Attack Type", style="cyan")
            attacks_table.add_column("Count", style="red", justify="right")
            attacks_table.add_column("% of Total", style="yellow", justify="right")
            
            total = self.stats['total_alerts']
            for attack, count in sorted(self.stats['attacks_detected'].items(), 
                                       key=lambda x: x[1], reverse=True):
                percentage = (count / total * 100) if total > 0 else 0
                attacks_table.add_row(
                    attack.replace('_', ' ').title(),
                    str(count),
                    f"{percentage:.1f}%"
                )
            
            console.print(attacks_table)
        else:
            console.print("\n[yellow]  No attacks detected[/yellow]")
        
        # Save results to file
        self._save_results()
    
    def _save_results(self):
        """Save results to JSON file"""
        results_file = Path('tests/results') / f"test_results_{int(time.time())}.json"
        results_file.parent.mkdir(exist_ok=True)
        
        results = {
            'pcap_file': str(self.pcap_path),
            'timestamp': time.time(),
            'statistics': dict(self.stats),
            'attacks_detected': dict(self.stats['attacks_detected'])
        }
        
        # Remove non-serializable items
        if 'flow_labels' in results['statistics']:
            del results['statistics']['flow_labels']
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        console.print(f"\n[green]   Results saved to: {results_file}[/green]")
    
    def cleanup(self):
        """Cleanup resources"""
        self.db.close()

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test ML detection on PCAP files')
    parser.add_argument('pcap', help='Path to PCAP file')
    parser.add_argument('--csv', help='Path to CICIDS CSV for ground truth (optional)')
    parser.add_argument('--chunk-size', type=int, default=1000, 
                       help='Packets to process per chunk (default: 1000)')
    parser.add_argument('--db', default='test_ml.db', 
                       help='Database path (default: test_ml.db)')
    
    args = parser.parse_args()
    
    # Verify PCAP exists
    if not Path(args.pcap).exists():
        console.print(f"[red]❌ PCAP file not found: {args.pcap}[/red]")
        return 1
    
    # Run test
    tester = MLDetectionTester(args.pcap, args.db, args.chunk_size)
    
    # Load labels if provided
    if args.csv and Path(args.csv).exists():
        tester.load_cicids_labels(args.csv)
    
    try:
        # Process PCAP
        tester.process_pcap_chunked()
        
        # Print results
        tester.print_results()
        
        return 0
        
    except KeyboardInterrupt:
        console.print("\n[yellow]  Interrupted by user[/yellow]")
        return 1
    
    except Exception as e:
        console.print(f"\n[red]❌ Test failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        tester.cleanup()

if __name__ == "__main__":
    sys.exit(main())