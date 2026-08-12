from scapy.all import sniff, IP, TCP, UDP, ICMP

interface = "VMware Network Adapter VMnet1" 

def handle_packet(packet):
    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst


    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        print(f"TCP {src}:{sport}  {dst}:{dport}")
    elif ICMP in packet:
        print(f"ICMP {src} {dst}")
    else:
        print(f"IP {src} {dst} (other)")

def main():
    print(f"sniffing on {interface} press Ctrl-c to stop")
    sniff(iface=interface, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()