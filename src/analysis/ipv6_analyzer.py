class IPv6Analyzer:
    
    def __init__(self):
        self.extension_headers = []
    
    def analyze(self, packet):
        if not packet.haslayer('IPv6'):
            return None
        
        ipv6 = packet['IPv6']
        src_ip = ipv6.src
        dst_ip = ipv6.dst
        next_header = ipv6.nh
        hop_limit = ipv6.hlim
        flow_label = ipv6.fl
        traffic_class = ipv6.tc
        payload_length = ipv6.plen
        
        return {
            "version": 6,
            "src_ip": self.compress_address(src_ip),
            "dst_ip": self.compress_address(dst_ip),
            "next_header": next_header,
            "hop_limit": hop_limit,
            "flow_label": flow_label,
            "traffic_class": traffic_class,
            "payload_length": payload_length,
        }
    
    def compress_address(self, addr):
        blocks = addr.lower().split(":")
        blocks = [block.lstrip('0') or '0' for block in blocks]

        longest_start = -1
        longest_len = 0
        i=0
        while i < len(blocks):
            if blocks[i] == "0":
                j=i
                while j < len(blocks) and blocks[j] == "0":
                    j+=1
                length = j-i
                if length > longest_len:
                    longest_len = length
                    longest_start = i
                i=j
            else:
                i+=1

        if longest_len > 1:
            blocks = (
                blocks[:longest_start]
                + ['']
                + blocks[longest_start + longest_len:]
            )

        compressed = ':'.join(blocks)

        # edge cases (:: at start or end)
        if compressed.startswith('::'):
            pass
        elif compressed.startswith(':'):
            compressed = ':' + compressed

        if compressed.endswith('::'):
            pass
        elif compressed.endswith(':') and not compressed.endswith('::'):
            compressed = compressed + ':'

        return compressed

        