import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from scapy.all import sniff, rdpcap
import sys
import os
import time
#  to add the root to the path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, PROJECT_ROOT)

# analyzers
from src.storage.database import NetSenseDB
from src.analysis.arp_analyzer import ARPAnalyzer
from src.analysis.ethernet_decoder import EthernetDecoder
from src.analysis.icmp_analyzer import ICMPAnalyzer
from src.analysis.ipv4_analyzer import IPv4Analyzer
from src.analysis.ipv6_analyzer import IPv6Analyzer
from src.analysis.protocol_stats import ProtocolStatistics
from src.analysis.dns_analyzer import DNSAnalyzer
from src.analysis.http_analyzer import HTTPAnalyzer

app = typer.Typer(help="Netsense - For making the internet to make more sense to you")
console = Console()
# global instances for all analyzers classes
db = NetSenseDB()
eth_decoder = EthernetDecoder()
arp_analyzer = ARPAnalyzer()
icmp_analyzer = ICMPAnalyzer()
ipv4_analyzer = IPv4Analyzer()
ipv6_analyzer = IPv6Analyzer()
http_analyzer = HTTPAnalyzer()
dns_analyzer = DNSAnalyzer()
stats_collector = ProtocolStatistics()

@app.command()
def capture(
    count: int = typer.Option(10, "--count", "-c", help = "Number of packets to be captured"),
    interface: str = typer.Option(None, "--interface", "-i", help = "network interface whose packets to be captured"),
    filter: str = typer.Option(None, "--filter", "-f", help= "BPF filter"),
    save: bool = typer.Option(True, "--save/--no-save", help = "Save to the DB"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help= "To show the detailed packet information"),
):
    """
    Flags: 
        -c/--count: for defining number of packets to be captured
        -i/--interface: interface to be used
        -f/--filter: bpf syntax filter
        --save/--no-save: to save in the db or not
        -v/--verbose: bool to show the detailed information
"""

    console.print(f"[bold cyan] Starting the packet capture.... [/bold cyan]")
    console.print(f"Interface: {interface or 'default'}")
    console.print(f"Count: {count}")
    console.print(f"Filter: {filter or None}")
    console.print(f"Save to DB: {'Yes' if save else 'No'}\n")
    console.print(f"Verbose: [yellow]{'Yes' if verbose else 'No'}[/yellow]\n")


    packet_count = [0]
    start_time = time.time()

    def packet_handler(packet):
        packet_count[0] += 1
        if not verbose:
            console.print(f"[dim] Capturing... {packet_count[0]}/{count} packets[/dim]", end="\r")
        console.print(f"[dim]Packet {packet_count[0]}/{count}[/dim]", end="\r")
        
        # basic copy of packet data
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
                'interface': interface or 'default',
                'flow_id': None
        }
        
        # Ethernet
        if packet.haslayer('Ether'):
            eth_info = eth_decoder.decode(packet)
            packet_data['src_mac'] = eth_info['src_mac']
            packet_data['dst_mac'] = eth_info['dst_mac']
            packet_data['ether_type'] = eth_info['ether_type_name']
            stats_collector.update(eth_info)

            if verbose:
                console.print(f"[cyan]→[/cyan] {eth_info['src_mac']} → {eth_info['dst_mac']} ({eth_info['ether_type_name']})")

        # ARP
        if packet.haslayer('ARP'):
            arp_info = arp_analyzer.analyze(packet)
            if arp_info:
                stats_collector.update(arp_info)
                if verbose:
                    console.print(f"  [yellow]ARP {arp_info['type']}:[/yellow] {arp_info['sender_ip']} is-at {arp_info['sender_mac']}")
                
                # for spoofing alerts
                if arp_info.get('alert'):
                    alert = arp_info['alert']
                    console.print(f"  [bold red]  SPOOFING: {alert['ip']} changed from {alert['old_mac']} to {alert['new_mac']}[/bold red]")
        
        # IP
        if packet.haslayer('IP'):
            ipv4_info = ipv4_analyzer.analyze(packet)
            if ipv4_info:
                packet_data['src_ip'] = ipv4_info['src_ip']
                packet_data['dst_ip'] = ipv4_info['dst_ip']
                packet_data['ip_protocol'] = ipv4_info['protocol_name']
                packet_data['ttl'] = ipv4_info['ttl']
                stats_collector.update(ipv4_info)


                if verbose:
                    console.print(f"  [green]IPv4:[/green] {ipv4_info['src_ip']} → {ipv4_info['dst_ip']} ({ipv4_info['protocol_name']}) TTL={ipv4_info['ttl']}")
                    if ipv4_info['is_fragmented']:
                        console.print(f"    [red]  Fragmented packet![/red]")

                # TCP
                if packet.haslayer('TCP'):
                    packet_data['src_port'] = packet['TCP'].sport
                    packet_data['dst_port'] = packet['TCP'].dport
                    packet_data['tcp_flags'] = str(packet['TCP'].flags)

                    if save:
                        flow_id = db.get_flow_id(
                            ipv4_info['src_ip'],
                            ipv4_info['dst_ip'],
                            packet['TCP'].sport,
                            packet['TCP'].dport,
                            'TCP'
                        )

                        packet_data['flow_id'] = flow_id
                        db.update_flow(flow_id, packet_data)
                    
                    if verbose:
                        console.print(f"    [blue]TCP:[/blue] {packet['TCP'].sport} → {packet['TCP'].dport} [{packet['TCP'].flags}]")
                # UDP
                elif packet.haslayer('UDP'):
                    packet_data['src_port'] = packet['UDP'].sport
                    packet_data['dst_port'] = packet['UDP'].dport

                    if save:
                        flow_id = db.get_flow_id(
                            ipv4_info['src_ip'],
                            ipv4_info['dst_ip'],
                            packet['UDP'].sport,
                            packet['UDP'].dport,
                            'UDP'
                        )
                        packet_data['flow_id'] = flow_id
                        db.update_flow(flow_id, packet_data)

                    if verbose:
                        console.print(f"    [magenta]UDP:[/magenta] {packet['UDP'].sport} → {packet['UDP'].dport}")
    
        # ICMP
        if packet.haslayer('ICMP'):
            icmp_info = icmp_analyzer.analyze(packet)
            if icmp_info:
                stats_collector.update(icmp_info)
                if verbose: 
                    console.print(f"    [yellow]ICMP:[/yellow] {icmp_info['type']}")
                    if icmp_info.get('rtt'):
                        console.print(f"      [green]⚡ RTT: {icmp_info['rtt']*1000:.2f} ms[/green]")
        
        # IPV6 
        if packet.haslayer('IPv6'):
            ipv6_info = ipv6_analyzer.analyze(packet)
            if ipv6_info:
                stats_collector.update(ipv6_info)
                if verbose:
                    console.print(f"  [green]IPv6:[/green] {ipv6_info['src_ip']} → {ipv6_info['dst_ip']}")
        
        # HTTP/HTTPS
        if packet.haslayer('TCP') and (packet['TCP'].dport in [80, 443] or packet['TCP'].sport in [80, 443]):
            http_info = http_analyzer.analyze(packet)
            if http_info:
                if verbose:
                    if http_info['type'] == 'HTTP_REQUEST':
                        console.print(f"    [cyan] HTTP {http_info['method']}: [/cyan]{http_info['full_url']}")
                    elif http_info['type'] == 'HTTP_RESPONSE':
                        console.print(f"    [cyan] HTTP {http_info['status_code']}: [/cyan]{http_info['status_text']}")
                    elif http_info['type'] == 'TLS_HANDSHAKE':
                        console.print(f"    [blue] HTTPS: [/blue] {http_info['handshake_type']} {http_info['tls_version']}")

        # DNS
        if packet.haslayer('DNS'):
            dns_info = dns_analyzer.analyze(packet)
            if dns_info and verbose:
                if dns_info['type'] == 'DNS_QUERY':
                    console.print(f"    [yellow] DNS Query: [/yellow] {dns_info['query_name']} {dns_info['query_type']}")
                if dns_info['type'] == 'DNS_RESPONSE':
                    status = dns_info['response_status']
                    if dns_info['answers']:
                        console.print(f"    [green] DNS Response:[/green] {status} - {len(dns_info['answers'])} answers")
                    else:
                        console.print(f"    [red] DNS Response:[/red] {status}")

        if save and 'src_mac' in packet_data:
            try:
                db.insert_packet(packet_data)
            except Exception as e:
                if verbose:
                    console.print(f"[red]DB Error: {e}[/red]")


    try:
        sniff(
            prn=packet_handler,
            count=count,
            iface=interface,
            filter=filter,
            store=False
        )

        elapsed_time = time.time() - start_time
        
        console.print(f"\n[bold green] Captured {packet_count[0]} packets in {elapsed_time:.2f}s![/bold green]")
        console.print(f"   Rate: {packet_count[0]/elapsed_time:.1f} packets/sec\n")
        
        show_stats()
    
    except PermissionError:
        console.print("[bold red]Error: Need root Privileges for this operation")
        console.print("Run with sudo netsense capture")
    except KeyboardInterrupt:
        console.print(f"\n[yellow]  Interrupted! Captured {packet_count[0]} packets[/yellow]")
        show_stats()
    except Exception as e:
        console.print(f"[bold red]❌ Error: {e}[/bold red]")


@app.command()
def stats(
    last: int = typer.Option(None, "--last", help="to show last N packets"),
):
    """
    Flags:
        --last:; to define the N packets
"""
    console.print("[bold cyan] NetSense Database Statistics[/bold cyan]\n")
    db_stats = db.get_statistics()
    
    # summary table
    summary_table = Table(title="Summary", show_header=False)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("value", style="yellow")

    summary_table.add_row("Total Packets", f"{db_stats['total_packets']:,}")
    summary_table.add_row("Total Bytes", f"{db_stats['total_bytes']:,}")
    summary_table.add_row("Active Flows", str(db_stats['active_flows']))

    console.print(summary_table)
    console.print()

    # protocol distrbution table
    table = Table(title="Protocol Distribution")
    table.add_column("Protocol", style="cyan")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right", style="green")
    
    total = db_stats['total_packets']
    if total>0:
        for proto, count in db_stats.get('protocol_distribution', {}).items():
            percentage = (count/total) * 100
            table.add_row(proto, str(count), f"{percentage:.1f}%")
    
    console.print(table)
    console.print()

    # Top talkers
    if db_stats.get('top_source_ips'):
        talkers_table = Table(title="Top Source IPs")
        talkers_table.add_column("IP Address", style="cyan")
        talkers_table.add_column("Packet Count", justify="right", style="magenta")
        
        for ip_info in db_stats['top_source_ips'][:10]:
            talkers_table.add_row(
                ip_info['src_ip'],
                str(ip_info['packet_count'])
            )
        
        console.print(talkers_table)

    # to show the recent packets using last
    if last:
        console.print(f"\n[bold]Last {last} Packets:[/bold]\n")
        packets = db.get_packets(limit=last)
        
        pkt_table = Table()
        pkt_table.add_column("Time", style="dim")
        pkt_table.add_column("Source → Destination", style="cyan")
        pkt_table.add_column("Protocol", style="yellow")
        pkt_table.add_column("Size", style="green")
        
        for pkt in packets[:20]:  
            timestamp = time.strftime('%H:%M:%S', time.localtime(pkt.get('timestamp', 0)))
            src = pkt.get('src_ip') or pkt.get('src_mac', 'N/A')
            dst = pkt.get('dst_ip') or pkt.get('dst_mac', 'N/A')
            proto = pkt.get('ip_protocol', 'N/A')
            size = pkt.get('packet_size', 0)
            
            pkt_table.add_row(
                timestamp,
                f"{src} → {dst}",
                proto,
                f"{size} B"
            )
        
        console.print(pkt_table)

@app.command()
def query(
    src_ip: str = typer.Option(None, "--src", help="Source IP"),
    dst_ip: str = typer.Option(None, "--dst", help="Destination IP"),
    protocol: str = typer.Option(None, "--protocol", "-p", help="Protocol : UDP/TCP/ICMP"),
    limit: int = typer.Option(10, "--limit", "-l", help="number of results"),    
):
    """
    Flags:
        --src: source ip
        --dst: dstination ip
        --protocol/-p: TCP/UDP/ICMP
        --limit/-l: number of result
"""
    console.print("[bold cyan]Querying database...[/bold cyan]\n")
    
    filters = {}
    if src_ip:
        filters['src_ip'] = src_ip
    if dst_ip:
        filters['dst_ip'] = dst_ip
    if protocol:
        filters['protocol'] = protocol.upper()

    packets = db.get_packets(limit=limit,filters=filters)

    console.print(f"Found [yellow]{len(packets)}[/yellow] packets\n")
    
    if not packets:
        console.print("[dim]No packets found for the matching criteria[/dim]")
        return
    
    # taken the min with 20 for having the display less clutter
    table = Table(title=f"Query Results (showing {min(len(packets), 20)})")
    table.add_column("ID", style="dim")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Src → Dst", style="yellow")
    table.add_column("Protocol", style="green")
    table.add_column("Ports", style="magenta")
    table.add_column("Size", style="blue")

    for pkt in packets[:20]: # first 20 packets;
        pkt_id = str(pkt.get('id', "N/A"))
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.get('timestamp', 0)))
        src_ip = pkt.get('src_ip', "N/A")
        dst_ip = pkt.get('dst_ip', "N/A")
        proto = pkt.get('ip_protocol', 'N/A')
        src_port = pkt.get('src_port')
        dst_port = pkt.get('dst_port')

        ports = f"{src_port}→{dst_port}" if src_port and dst_port else 'N/A'
        size = f"{pkt.get('packet_size', 0)} B"
        
        table.add_row(pkt_id, timestamp, f"{src_ip}→{dst_ip}", proto, ports, size)

    console.print(table)

@app.command()
def export(
    format: str = typer.Argument(..., help="export format (json/csv)"),
    output: str = typer.Argument(..., help="output file"),
    limit: int = typer.Option(1000, "--limit", "-l", help="Number of packets"),
):
    """
        netsense export json output.json
        netsense export csv traffic.csv --limit 1000
"""
    console.print(f"[bold cyan]Exporting to {format.upper()}...[/bold cyan]\n")

    with console.status(f"[bold green]Fetching {limit} packets..."):
        packets = db.get_packets(limit=limit)
    
    if not packets:
        console.print("[red]No packets to export![/red]")
        return
    
    try:
        if format.lower() == 'json':
            import json
            with open(output, 'w') as f:
                json.dump(packets, f, indent=2, default=str)
        elif format.lower() == 'csv':
            import csv
            if packets:
                keys = packets[0].keys()
                with open(output, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(packets)
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            console.print("Supported formats: json, csv")
            return
        
        file_size = os.path.getsize(output)
        console.print(f"[bold green]Exported {len(packets)} packets to {output}[/bold green]")
        console.print(f"   File size: {file_size:,} bytes")
        
    except Exception as e:
        console.print(f"[bold red]❌ Export failed: {e}[/bold red]")


@app.command()
def analyze(
    file: str = typer.Argument(..., help="PCAP file to analyze"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save to database"),
):
    """
        netsense analyze capture.pcap
        netsense analyze traffic.pcap --no-save
    """
    console.print(f"[bold cyan]Analyzing {file}...[/bold cyan]\n")
    
    if not os.path.exists(file):
        console.print(f"[bold red]❌ File not found: {file}[/bold red]")
        return
    
    try:
        # Read PCAP file
        with console.status("[bold green]Reading PCAP file..."):
            packets = rdpcap(file)
        
        console.print(f"Found [yellow]{len(packets)}[/yellow] packets\n")
        
        # Process packets
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing packets...", total=len(packets))
            
            for i, packet in enumerate(packets):
                # Analyze through all layers (similar to capture)
                if packet.haslayer('Ether'):
                    eth_info = eth_decoder.decode(packet)
                    stats_collector.update(eth_info)
                
                if packet.haslayer('ARP'):
                    arp_info = arp_analyzer.analyze(packet)
                    if arp_info:
                        stats_collector.update(arp_info)
                
                if packet.haslayer('IP'):
                    ipv4_info = ipv4_analyzer.analyze(packet)
                    if ipv4_info:
                        stats_collector.update(ipv4_info)
                
                if packet.haslayer('IPv6'):
                    ipv6_info = ipv6_analyzer.analyze(packet)
                    if ipv6_info:
                        stats_collector.update(ipv6_info)
                
                if packet.haslayer('ICMP'):
                    icmp_info = icmp_analyzer.analyze(packet)
                    if icmp_info:
                        stats_collector.update(icmp_info)
                
                progress.update(task, advance=1)
        
        console.print("\n[bold green]Analysis complete![/bold green]\n")
        
        # Show statistics
        show_stats()
    
    except Exception as e:
        console.print(f"[bold red]Analysis failed: {e}[/bold red]")


def show_stats():
    summary = stats_collector.get_summary()
    
    console.print("\n[bold]Session Statistics:[/bold]")
    console.print(f"  Total Packets: {summary['total_packets']}")
    console.print(f"  Total Bytes: {summary['total_bytes']:,}")
    console.print(f"  IPv4: {summary['ipv4']['total']}")
    console.print(f"  IPv6: {summary['ipv6']['total']}")
    console.print(f"  ARP: {summary['arp']['requests'] + summary['arp']['replies']}")
    console.print(f"  ICMP: {summary['icmp']['total']}")

    http_stats = http_analyzer.get_statistics()
    if http_stats['http_requests'] > 0 or http_stats['https_connections'] > 0:
        console.print(f"\n[bold] Application Layer:[/bold]")
        console.print(f"  HTTP Requests: [cyan]{http_stats['http_requests']}[/cyan]")
        console.print(f"  HTTP Responses: [cyan]{http_stats['http_responses']}[/cyan]")
        console.print(f"  HTTPS Connections: [blue]{http_stats['https_connections']}[/blue]")
        console.print(f"  TLS Handshakes: [blue]{http_stats['tls_handshakes']}[/blue]")
    
    # Add DNS stats
    dns_stats = dns_analyzer.get_statistics()
    if dns_stats['total_queries'] > 0:
        console.print(f"\n[bold] DNS Activity:[/bold]")
        console.print(f"  Total Queries: [yellow]{dns_stats['total_queries']}[/yellow]")
        console.print(f"  Resolved: [green]{dns_stats['resolved_queries']}[/green]")
        console.print(f"  Avg Resolution Time: [green]{dns_stats['avg_resolution_time']*1000:.1f}ms[/green]")
        
        if dns_stats['top_domains']:
            console.print(f"  Top Domains: [dim]{', '.join([d[0] for d in dns_stats['top_domains'][:3]])}[/dim]")



if __name__ == "__main__":
    app()
