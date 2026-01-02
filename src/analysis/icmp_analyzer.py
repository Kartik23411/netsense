import time
class ICMPAnalyzer:
    ICMP_TYPES = {
        0:  "Echo Reply",
        3:  "Destination Unreachable",
        5:  "Redirect",
        8:  "Echo Request",
        9:  "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem",
        13: "Timestamp",
        14: "Timestamp Reply",
        40: "Photuris",
        41: "Experimental Mobility Protocols (Seamoby)",
        42: "Extended Echo Request",
        43: "Extended Echo Reply",
        253: "RFC3692-style Experiment 1",
        254: "RFC3692-style Experiment 2",
        255: "Reserved"
    }
    
    def __init__(self):
        self.ping_tracker = {}  # for tracking ping seq
    
    def analyze(self, packet):
        if not packet.haslayer('ICMP'):
            return None
        
        icmp = packet['ICMP']
        type = icmp.type
        type_name = self.ICMP_TYPES.get(type, "Unknown")
        code = icmp.code
        checksum = icmp.chksum
        id = icmp.id if hasattr(icmp, 'id') else None
        sequence = icmp.seq if hasattr(icmp, 'seq') else None

        rtt = None # it is the round trip time of the echo(ping) request i.e. time between request and reply

        if type == 8:
            self.ping_tracker[(id, sequence)] = time.time()
        elif type == 0:
            key = (id, sequence)
            if key in self.ping_tracker:
                rtt = time.time() - self.ping_tracker.pop(key)
        
        return {
            'type': type_name,
            'code': code,
            'checksum': checksum,
            'id': id,
            'sequence': sequence,
            'rtt': rtt
        }