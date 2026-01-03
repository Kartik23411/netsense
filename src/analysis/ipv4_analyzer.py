class IPv4Analyzer:
    # IP Protocols
    PROTOCOLS = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6-in-IPv4",
        47: "GRE",
        50: "ESP",
        51: "AH",
        89: "OSPF",
        132: "SCTP",
    }
    
    # Flags
    FLAG_RESERVED = 0x4
    FLAG_DF = 0x2  
    FLAG_MF = 0x1  
    
    def __init__(self):
        self.fragment_tracker = {}  # for tracking the fragmented packets
    
    def get_protocol_name(self, proto):
        return self.PROTOCOLS.get(proto, f"Unknown({proto})")

    def analyze(self, packet):

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
        protocol_name = self.get_protocol_name(protocol)
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
            "protocol_name": protocol_name,
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
        flag_df = int(ip.flags.DF)
        fragment_offset = ip.frag
        if flag_df and (flag_mf or fragment_offset > 0):
            return True
        else:
            return False