from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Display source and destination IPs and the protocol
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol (TCP, UDP, etc.)
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Packet: {protocol} | Source: {ip_src} | Destination: {ip_dst}")
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            print(f"Payload: {packet[IP].payload}")

# Capture packets on the network interface
sniff(prn=packet_callback, store=0)
