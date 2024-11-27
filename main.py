from scapy.all import sniff, TCP, UDP, Raw

def packet_callback(packet):
    """
    Callback function for each captured packet.
    Filters for packets containing TCP/UDP and Raw payload.
    """
    try:
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            # Check for TCP/UDP layer and print details
            sport = packet.sport
            dport = packet.dport
            payload = packet[Raw].load if packet.haslayer(Raw) else b"(No Data)"
            
            print(f"Packet: {packet.summary()}")
            print(f"Source Port: {sport}, Destination Port: {dport}")
            print(f"Payload: {payload.decode(errors='ignore')}")
            print("-" * 80)
    except Exception as e:
        print(f"Error processing packet: {e}")

def sniff_packets(port, iface="any"):
    """
    Sniffs packets passively on a specific port.
    Args:
        port: The port number to filter traffic.
        iface: The interface to listen on ("any" for all interfaces).
    """
    print(f"Sniffing on port {port}...")
    sniff(
        iface=iface,
        filter=f"port {port}",  # Berkeley Packet Filter syntax
        prn=packet_callback,
        store=False  # Don't store packets in memory
    )

if __name__ == "__main__":
    try:
        sniff_port = int(input("Enter the port to sniff: "))
        sniff_packets(sniff_port)
    except ValueError:
        print("Please enter a valid port number.")
    except KeyboardInterrupt:
        print("\nSniffing stopped.")
