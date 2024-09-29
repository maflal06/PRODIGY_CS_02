from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process each captured packet
def packet_handler(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\nNew Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Check the protocol and display relevant information
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Source Port: {tcp_layer.sport} -> Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Source Port: {udp_layer.sport} -> Destination Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("Protocol: ICMP")
        else:
            print(f"Protocol: {ip_layer.proto}")

        # Print payload data, if present
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload or packet[UDP].payload)
            if payload:
                print(f"Payload: {payload[:30]}...")  # Show first 30 bytes of payload for brevity
            else:
                print("No payload data")
    else:
        print("Non-IP packet detected")

# Function to start sniffing network traffic
def start_sniffer(interface):
    print(f"[*] Starting packet sniffer on {interface}")
    # Capture packets on the specified interface, sending them to packet_handler
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    # Specify the network interface to sniff on (e.g., "eth0", "wlan0", "en0", "lo")
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    start_sniffer(interface)
