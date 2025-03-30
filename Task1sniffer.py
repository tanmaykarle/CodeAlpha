from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if packet.haslayer(TCP):
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
        else:
            proto_name = "Other"
            src_port = "N/A"
            dst_port = "N/A"

        print(f"[{proto_name}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Start sniffing network packets
print("Starting Network Sniffer...")
sniff(prn=packet_callback, store=False)
