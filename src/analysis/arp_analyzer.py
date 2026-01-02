import time
class ARPAnalyzer:
    # Opcodes
    ARP_REQUEST = 1
    ARP_REPLY = 2
    
    def __init__(self):
        self.arp_cache = {}  # for the ip - mac mapping
        self.arp_history = []  # for tracking the traffic of arp
        self.spoofing_alerts = [] # for alerting in case of spoofing found
    
    def analyze(self, packet):
        if not packet.haslayer('ARP'):
            return None
        
        arp = packet['ARP']
        
        opcode = arp.op
        sender_mac = arp.hwsrc
        sender_ip = arp.psrc
        target_mac = arp.hwdst
        target_ip = arp.pdst

        is_request = (opcode == self.ARP_REQUEST)
        is_reply = (opcode == self.ARP_REPLY)
        
        alert = self.detect_spoofing(sender_ip, sender_mac)
        self.update_cache(sender_ip, sender_mac)
        
        event = {
            "opcode": opcode,
            "type": "Request" if is_request else "Reply",
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_mac": target_mac,
            "target_ip": target_ip,
            "alert": alert
        }

        self.arp_history.append(event)
        return event
    
    def detect_spoofing(self, ip, mac):
        
        if ip in self.arp_cache:
            old_mac = self.arp_cache[ip]["mac"]
            if old_mac != mac:
                alert = {
                    "type": "ARP_SPOOFING",
                    "ip": ip,
                    "old_mac": self.arp_cache[ip]["mac"],
                    "new_mac": mac,
                    "timestamp": time.time()
                }
                self.spoofing_alerts.append(alert)
                return alert
        return None
            
    
    def update_cache(self, ip, mac):
        if ip not in self.arp_cache:
            self.arp_cache[ip] = {'mac': mac, 'timestamp': time.time()}
        else:
            self.arp_cache[ip]['timestamp'] = time.time()