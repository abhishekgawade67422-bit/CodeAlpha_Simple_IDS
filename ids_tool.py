import sys
from scapy.all import sniff, IP, TCP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # 1. Detect SYN Scan (Potential Port Scanning)
        if packet.haslayer(TCP):
            if packet[TCP].flags == "S":
                print(f"[!] ALERT: Potential SYN Scan detected from {src_ip} to {dst_ip} on port {packet[TCP].dport}")

        # 2. Detect Large ICMP Packets (Potential Ping of Death)
        if packet.haslayer(ICMP):
            if len(packet) > 1024:
                print(f"[!] ALERT: Suspiciously large ICMP packet from {src_ip}")

def start_ids():
    print("--- CodeAlpha IDS Tool Started ---")
    print("Monitoring network for suspicious activities...")
    try:
        # Sniffing packets (Requires Admin/Root privileges)
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nIDS Tool stopped by user.")
        sys.exit()

if __name__ == "__main__":
    start_ids()