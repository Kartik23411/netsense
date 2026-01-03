class ProtocolStatistics:

    def __init__(self):
        self.stats = {
            'ethernet': {},
            'arp': {'requests': 0, 'replies': 0},
            'ipv4': {'total': 0, 'protocols': {}},
            'ipv6': {'total': 0},
            'icmp': {'total': 0, 'types': {}},
            'total_packets': 0,
            'total_bytes': 0,
        }
    
    def update(self, packet_info):
        if not packet_info:
            return
        
        self.stats['total_packets']+=1
        
        if 'frame_size' in packet_info:
            self.stats['total_bytes'] += packet_info['frame_size']

        # ethernet
        if 'ether_type_name' in packet_info:
            eth_type = packet_info['ether_type_name']
            self.stats['ethernet'][eth_type] = (
                self.stats['ethernet'].get(eth_type, 0) + 1
            )

        # arp
        if packet_info.get('type') in ('Request', 'Reply') and 'sender_ip' in packet_info:
            if packet_info['type'] == 'Request':
                self.stats['arp']['requests'] += 1
            elif packet_info['type'] == 'Reply':
                self.stats['arp']['replies'] += 1

        # ipv4
        if 'protocol' in packet_info and packet_info.get('version') == 4:
            self.stats['ipv4']['total'] += 1
            proto = packet_info['protocol']
            self.stats['ipv4']['protocols'][proto] = (
                self.stats['ipv4']['protocols'].get(proto, 0) + 1
            )
        elif 'protocol' in packet_info and 'ttl' in packet_info and 'version' not in packet_info:
            self.stats['ipv4']['total'] += 1
            proto = packet_info['protocol']
            self.stats['ipv4']['protocols'][proto] = (
                self.stats['ipv4']['protocols'].get(proto, 0) + 1
            )
            
        # ipv6
        if packet_info.get('version') == 6 or ('hop_limit' in packet_info and 'flow_label' in packet_info):
            self.stats['ipv6']['total'] += 1

        # icmp
        if 'type' in packet_info and 'checksum' in packet_info:
            if packet_info.get('type') not in ('Request', 'Reply'):
                self.stats['icmp']['total'] += 1
                icmp_type = packet_info['type']
                self.stats['icmp']['types'][icmp_type] = (
                    self.stats['icmp']['types'].get(icmp_type, 0) + 1
                )

    
    def get_summary(self):
        return self.stats
    
    def get_protocol_distribution(self):
        total = self.stats['total_packets']
        if total == 0:
            return {}
        
        distribution = {}

        for proto, count in self.stats['ethernet'].items():
            distribution[f"Ethernet_{proto}"] = (count / total) * 100

        distribution['IPv4'] = (self.stats['ipv4']['total'] / total) * 100
        distribution['IPv6'] = (self.stats['ipv6']['total'] / total) * 100

        arp_total = self.stats['arp']['requests'] + self.stats['arp']['requests']
        distribution["ARP"] = (arp_total / total) * 100
        return distribution