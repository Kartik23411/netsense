import time

class DNSAnalyzer:

    DNS_TYPES = {
        1: 'A',      # IPv4 address
        2: 'NS',     # Name server
        5: 'CNAME',  # Canonical name
        6: 'SOA',    # Start of authority
        12: 'PTR',   # Pointer record
        15: 'MX',    # Mail exchange
        16: 'TXT',   # Text record
        28: 'AAAA',  # IPv6 address
        33: 'SRV',   # Service locator
    }

    def __init__(self):
        self.queries = {}
        self.resolved = []
        self.resolution_times = []
        self.popular_domains = {}
        self.tunnel_suspects = []

    def analyze(self, packet):

        if not packet.haslayer('DNS'):
            return None
        
        dns = packet['DNS']

        ip_layer = None
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
        elif packet.haslayer('IPv6'):
            ip_layer = packet['IPv6']

        if dns.qr == 0: #dns query
            return self.process_query(packet, dns, ip_layer)
        
        elif dns.qr == 1: #dns response
            return self.process_response(packet, dns, ip_layer)
        
        return None
    
    def process_query(self, packet, dns, ip_layer):

        if not dns.qd: #no question detection
            return None
        
        query_name = dns.qd.qname.decode('utf-8', errors = 'ignore').rstrip('.')
        query_type = dns.qd.qtype
        transaction_id = dns.id

        query_info = {
            "type": "DNS_QUERY",
            "transaction_id": transaction_id,
            "query_name": query_name,
            "query_type": self.DNS_TYPES.get(query_type, f"type_{query_type}"),
            "src_ip": ip_layer.src if ip_layer else None,
            "dst_ip": ip_layer.dst if ip_layer else None,
            "timestamp": time.time()
        }

        # Track query for matching with response
        self.queries[transaction_id] = query_info

        # track top domains
        domain = self.extract_domain(query_name)
        self.popular_domains[domain] = self.popular_domains.get(domain, 0) + 1

        # to check for it is tunnel suspect
        if self.is_tunnel_suspect(query_name):
            query_info['tunnel_suspect'] = True
            self.tunnel_suspects.append(query_info)

        return query_info

    def process_response(self, packet, dns, ip_layer):

        transaction_id = dns.id # to check and map with the queries

        query_info = self.queries.pop(transaction_id, 0)      

        answers = []

        if dns.an and dns.ancount > 0:
            try:
                answer_count = dns.ancount
                current = dns.an

                for i in range(answer_count):
                    if current:
                        try:
                            answer_data = {
                                "name": current.rrname.decode('utf-8', errors='ignore').rstrip('.'),
                                "type": self.DNS_TYPES.get(current.type, f"Type_{current.type}"),
                                "ttl": current.ttl,
                            }

                            # Extract the actual data based on type
                            if current.type == 1:  # A record
                                answer_data['data'] = current.rdata
                            elif current.type == 5:  # CNAME
                                try:
                                    answer_data['data'] = current.rdata.decode('utf-8', errors='ignore').rstrip('.')
                                except:
                                    answer_data['data'] = str(current.rdata)
                            elif current.type == 12:  # PTR
                                try:
                                    answer_data['data'] = current.rdata.decode('utf-8', errors='ignore').rstrip('.')
                                except:
                                    answer_data['data'] = str(current.rdata).strip('b').rstrip("'")
                            elif current.type == 28:  # AAAA
                                answer_data['data'] = current.rdata
                            else:
                                answer_data['data'] = str(current.rdata)[:100] # limiting to 100 to avoid large data

                            answers.append(answer_data)
                            current = current.payload if hasattr(current, 'payload') else None

                        except Exception as e:
                            break

            except Exception as e:
                pass

        response_info = {
            'type': 'DNS_RESPONSE',
            'transaction_id': transaction_id,
            'response_code': dns.rcode,
            'answer_count': dns.ancount,
            'answers': answers,
            'src_ip': ip_layer.src if ip_layer else None,
            'dst_ip': ip_layer.dst if ip_layer else None,
            'timestamp': time.time(),
        }

        rcode_names = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
        response_info['response_status'] = rcode_names.get(response_info['response_code'], 'UNKNOWN')

        # if query of same transaction id found then resolution time captured
        if query_info:
            resolution_time = response_info['timestamp'] - query_info['timestamp']
            response_info['resolution_time'] = resolution_time
            response_info['query_name'] = query_info['query_name']
            self.resolution_times.append(resolution_time)

            # updating the resolved requests lists
            self.resolved.append({
                'query': query_info,
                'response': response_info,
                'resolution_time': resolution_time,
            })

        return response_info
    
    def extract_domain(self, query_name):

        "Extract main domain from FQDN"
        parts = query_name.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return query_name
    
    def is_tunnel_suspect(self, query_name):
        """
        Used indicators like,
        - Very long subdomain names (> 50 chars)
        - High entropy (random-looking strings)
        - Unusual TLD usage
        - Excessive query rate to same domain
        """

        # Check length
        if len(query_name) > 50:
            return True
        
        # Check for long subdomains
        parts = query_name.split('.')
        for part in parts:
            if len(part) > 30:
                return True
        
        # Check for high number of subdomains
        if len(parts) > 5:
            return True
        
        return False
    
    def get_statistics(self):
        # to get the dns statisticsa
        avg_resolution = sum(self.resolution_times) / len(self.resolution_times) if self.resolution_times else 0
        # to get the top 10 
        top_domains = sorted(
            self.popular_domains.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_queries': len(self.resolved) + len(self.queries),
            'resolved_queries': len(self.resolved),
            'pending_queries': len(self.queries),
            'avg_resolution_time': avg_resolution,
            'tunnel_suspects': len(self.tunnel_suspects),
            'top_domains': top_domains,
        }