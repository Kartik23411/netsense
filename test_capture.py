from scapy.all import sniff

def packet_callback(packet):
    print(f"\n--- Packet {packet_callback.count} ---")
    print(packet.summary())
    packet_callback.count += 1


# Initialize
packet_callback.count = 1

def main():
    print("Starting packet capture... (sniffing 5 packets)")
    
    try:
        sniff(prn=packet_callback, count=5, store=False)
        print("\n✓ Packet capture complete!")
    except PermissionError:
        print("Error: This script requires administrator privileges.")
        print("Please run with: sudo python test_capture.py")
    except KeyboardInterrupt:
        print("\n\nPacket capture interrupted by user")


if __name__ == "__main__":
    main()
