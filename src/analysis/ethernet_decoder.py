import re
import os

def load_oui_map(path):
        oui_map = {}

        pattern = re.compile(
            r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$"
        )
        with open(path, "r", errors="ignore") as f:
            for line in f:
                match = pattern.match(line)
                if match:
                    oui = match.group(1).replace("-", "").lower()
                    vendor = match.group(2).strip()
                    oui_map[oui] = vendor

        return oui_map

class EthernetDecoder:
    # ether type frames
    ETHERTYPE_IPV4 = 0x0800
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_VLAN = 0x8100
    ETHERTYPE_IPV6 = 0x86DD

    ETHERTYPES = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x8100: "VLAN",
        0x86DD: "IPv6",
    }

    def __init__(self):
        # statistic specific dictionaries
        self.mac_cache = {}
        self.vlan_stats = {}

        base_dir = os.path.dirname(__file__)
        oui_path = os.path.join(base_dir, "../../ouidb.txt")

        self.oui_map = load_oui_map(oui_path)

    def decode(self, packet):    
        eth = packet['Ether']    
        src_mac = eth.src
        dst_mac = eth.dst
        ether_type = eth.type
        ether_type_name = self.ETHERTYPES.get(ether_type, f"Unknown (0x{ether_type:04x})")
        frame_size = len(packet)

        src_type = self.classify_mac(src_mac)
        dst_type = self.classify_mac(dst_mac)

        src_vendor = self.get_vendor(src_mac)
        dst_vendor = self.get_vendor(dst_mac)

        if src_mac not in self.mac_cache:
            self.mac_cache[src_mac] = {"count": 0, "classification": src_type, "vendor": src_vendor}
        self.mac_cache[src_mac]["count"]+=1

        if dst_mac not in self.mac_cache:
            self.mac_cache[dst_mac] = {"count": 0, "classification": dst_type, "vendor": dst_vendor}
        self.mac_cache[dst_mac]["count"]+=1

        vlan_info = self.parse_vlan_tag(packet)

        return {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_type": src_type,
            "dst_type": dst_type,
            "src_vendor": src_vendor,
            "dst_vendor": dst_vendor,
            "ether_type":ether_type,
            "ether_type_name": ether_type_name,
            "frame_size": frame_size,
            "vlan": vlan_info
        }

    def parse_vlan_tag(self, packet):
        if packet.haslayer('Dot1Q'):
            vlan_obj = packet['Dot1Q']
            id = vlan_obj.vlan
            priority = vlan_obj.prio
            dei = vlan_obj.dei
            # here dei is the drop eligible indicator for the vlan frame

            if id not in self.vlan_stats:
                self.vlan_stats[id] = {"count": 0, "priority": priority}
            self.vlan_stats[id]["count"]+=1
            return {
                "id": id,
                "priority": priority,
                "dei": dei,
            }
        else:
            return None
    
    def classify_mac(self, mac_address):

        """
        MAC format: XX:XX:XX:XX:XX:XX
        First byte determines type:
        - ff:ff:ff:ff:ff:ff = Broadcast
        - First byte LSB = 1 = Multicast  
        - First byte LSB = 0 = Unicast
        """
        if mac_address == "ff:ff:ff:ff:ff:ff":
            return "Broadcast"

        # special cases
        if mac_address == "00:00:00:00:00:00":
            return "Null/Invalid"
        if mac_address.startswith("aa:aa:03"):
            return "Cooked Capture"
        
        first_byte_hex = mac_address[0:2]
        first_byte_int = int(first_byte_hex, 16)
        
        # CHECKING LSB IS SET OR NOT
        if first_byte_int & 1: 
            return "Multicast"
        else:
            return "Unicast"

    def get_vendor(self, mac_address):
        if not mac_address:
            return "Unknown"
        
        if mac_address in self.mac_cache:
            return self.mac_cache[mac_address]["vendor"]
    
        oui = mac_address.replace(":", "").replace("-", "")[:6].lower()
        return self.oui_map.get(oui, "Unknown")

    