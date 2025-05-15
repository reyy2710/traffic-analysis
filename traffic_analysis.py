from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNS

def packet_callback(packet):
    if packet.haslayer(DNS):
        print("[DNS] Query:", packet[DNS].qd.qname.decode())
    elif packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port = packet[TCP].dport
        print(f"[HTTP] Packet from {ip_src} to {ip_dst}:{port}")

print("Starting packet sniffer... (Press Ctrl+C to stop)")
sniff(filter="port 53 or port 80", prn=packet_callback, store=0)
