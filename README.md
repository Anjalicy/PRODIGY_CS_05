# Python Packet Sniffer

A simple Python-based packet sniffer using the `scapy` library. This tool captures network traffic and displays information such as source and destination IP addresses, protocols, and packet payloads. It also allows filtering traffic (HTTP, HTTPS, DNS, or custom) and saving captured packets to a `.pcap` file for further analysis using tools like Wireshark.

## Features

- Capture and display the following packet details:
  - Source and Destination IP addresses
  - Protocols (TCP, UDP, etc.)
  - Payload data (if available)
- **Traffic filtering**:
  - Option to filter HTTP/HTTPS traffic, DNS traffic, or use custom filters.
- **Save captured packets** to a `.pcap` file for later analysis.
- Supports capturing up to a specified number of packets (default: 10, customizable).

## Requirements

- Python 3.x
- `scapy` library

You can install `scapy` using pip:

    pip install scapy
## Usage
1. Clone the Repository

        git clone https://github.com/yourusername/packet-sniffer.git
        cd packet-sniffer
2. Run the Packet Sniffer

Run the script with sudo to give it the necessary permissions to capture network traffic:

    sudo python3 packet.py
  3. Choose the Type of Traffic to Filter

You will be prompted to select a type of traffic to capture:

  Option 1: HTTP/HTTPS (ports 80 and 443)
  Option 2: DNS (port 53)
  Option 3: Custom filter (you can input any BPF (Berkeley Packet Filter) syntax for your filter)

Example custom filters:

  Capture SSH traffic: tcp port 22
  Capture ICMP (ping) traffic: icmp

4. Output

The script captures 10 packets by default (you can modify this in the code). It displays each packet's source and destination IP addresses, the protocol used, and any payload data (if available).

After capturing the packets, they are saved to a file called captured_traffic.pcap in the current directory. You can open this file in Wireshark for further analysis:
        
    wireshark captured_traffic.pcap
## Example Output
    Starting packet sniffer...
    Choose the type of traffic to filter:
    1. HTTP/HTTPS (Port 80 and 443)
    2. DNS (Port 53)
    3. Custom Filter (use BPF syntax)
    Enter the number of your choice: 1
    [+] Source: 10.0.2.15 --> Destination: 18.161.210.238 | Protocol: TCP
    [+] Payload: 
    [+] Source: 18.161.210.238 --> Destination: 10.0.2.15 | Protocol: TCP
    [+] Payload: "@j[L*f="
    [+] Source: 99.86.20.76 --> Destination: 10.0.2.15 | Protocol: TCP
    [+] Payload: "W\nL}%?Cݵ1kÍK"
    [+] Packets saved to captured_traffic.pcap
## Ethical Considerations

Ensure that you use this tool in environments where you have permission to capture network traffic. Unauthorized use of packet sniffers may violate privacy and security regulations. Always adhere to local laws and organizational policies when using this tool.
## License

This project is licensed under the MIT License - see the LICENSE file for details.



