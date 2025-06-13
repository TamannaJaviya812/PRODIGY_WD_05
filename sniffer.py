from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    print("=== Packet Captured ===")
    if IP in packet:
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} -> {ip_layer.dst}")

        if TCP in packet:
            print(f"[TCP] Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"[UDP] Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")
        
        if Raw in packet:
            print(f"[Payload] {packet[Raw].load[:50]}")  # show first 50 bytes

    print("========================\n")

# Start sniffing (requires admin/root privileges)
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(filter="ip", prn=packet_callback, store=False)
