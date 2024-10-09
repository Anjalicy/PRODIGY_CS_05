from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP

# List to store captured packets
captured_packets = []

# Callback function to handle each captured packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        proto_name = 'Unknown'

        if protocol == 6:  # TCP
            proto_name = 'TCP'
        elif protocol == 17:  # UDP
            proto_name = 'UDP'
        else:
            proto_name = str(protocol)
        
        print(f"[+] Source: {ip_src} --> Destination: {ip_dst} | Protocol: {proto_name}")
        
        # Display TCP/UDP payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                payload_data = bytes(packet[TCP].payload).decode('utf-8', 'ignore')
                print(f"[+] Payload: {payload_data}")
            except Exception as e:
                print(f"[!] Error reading payload: {e}")
        
        # Add the packet to the list of captured packets
        captured_packets.append(packet)

# Choose a filter: HTTP/HTTPS or DNS or customize your own filter
def choose_filter():
    print("Choose the type of traffic to filter:")
    print("1. HTTP/HTTPS (Port 80 and 443)")
    print("2. DNS (Port 53)")
    print("3. Custom Filter (use BPF syntax)")
    
    choice = input("Enter the number of your choice: ")
    
    if choice == '1':
        return "tcp port 80 or tcp port 443"  # HTTP/HTTPS
    elif choice == '2':
        return "udp port 53"  # DNS traffic
    elif choice == '3':
        custom_filter = input("Enter your custom filter: ")
        return custom_filter
    else:
        print("Invalid choice, defaulting to HTTP/HTTPS filter.")
        return "tcp port 80 or tcp port 443"

# Start sniffing with user-defined filtering
print("Starting packet sniffer...")

# Allow the user to select a filter
chosen_filter = choose_filter()

# Sniff packets based on the chosen filter
sniff(filter=chosen_filter, prn=packet_callback, count=10)

# Save the captured packets to a pcap file
pcap_file = "captured_traffic.pcap"
wrpcap(pcap_file, captured_packets)

print(f"[+] Packets saved to {pcap_file}")
