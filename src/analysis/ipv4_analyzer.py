class IPv4Analyzer:
    # IP Protocols
    PROTO_ICMP = 1
    PROTO_TCP = 6
    PROTO_UDP = 17
    
    # Flags
    FLAG_RESERVED = 0x4
    FLAG_DF = 0x2  
    FLAG_MF = 0x1  
    
    def __init__(self):
        self.fragment_tracker = {}  # for tracking the fragmented packets
    
    def analyze(self, packet):
        """
        Deep IPv4 analysis
        Returns: dict with all header fields
        """
        if not packet.haslayer('IP'):
            return None
        
        ip = packet['IP']
        
        # Basic fields
        version = ip.version
        ihl = ip.ihl  # Internet Header Length (in 32-bit words)
        header_size = ihl * 4  # Convert to bytes
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto
        ttl = ip.ttl
        flags = ip.flags
        df = int(flags.DF)
        mf = int(flags.MF)
        fragment_offset = ip.frag
        identification = ip.id
        checksum = ip.chksum
        
        # Check fragmentation
        is_fragmented = self.is_fragmented(ip)
        
        return {
            "version": version,
            "header_size": header_size,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "ttl": ttl,
            "identification": identification,
            "checksum": checksum,
            "is_fragmented": is_fragmented,
            "fragment_offset": fragment_offset if is_fragmented else None,
            "flag_df": df,
            "flag_mf": mf,
        }
    
    def is_fragmented(self, ip):
        flag_mf = int(ip.flags.MF)
        fragment_offset = ip.frag
        if flag_mf or fragment_offset > 0:
            return True
        else:
            return False