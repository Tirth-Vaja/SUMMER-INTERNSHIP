from scapy.all import sniff, IP, TCP, UDP, ICMP

# This function is called for every packet captured
def show_packet(packet):
    if IP in packet:
        print("========== Packet Captured ==========")
        print("Source IP: ", packet[IP].src)
        print("Destination IP: ", packet[IP].dst)
        print("Protocol: ", packet[IP].proto)
        if TCP in packet:
            print("[TCP] Source Port:", packet[TCP].sport, " Destination Port:", packet[TCP].dport)
        elif UDP in packet:
            print("[UDP] Source Port:", packet[UDP].sport, " Destination Port:", packet[UDP].dport)
        elif ICMP in packet:
            print("[ICMP] Type:", packet[ICMP].type, " Code:", packet[ICMP].code)
        print("Raw Content:", bytes(packet).hex()[:64], "...")
        print("=====================================")

print("Starting network sniffer... Press Ctrl+C to stop.")
sniff(prn=show_packet, store=0)