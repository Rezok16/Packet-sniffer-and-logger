from scapy.all import sniff, ARP

interface = "VMware Network Adapter VMnet1"

ip_to_mac = {}

def handle_packet(packet):
    if ARP not in packet:
        return

    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc

    print(f"[debug] ARP seen: {ip} is at {mac} (op={packet[ARP].op})}}")

    if ip == "0.0.0.0":
        return

    if ip in ip_to_mac and ip_to_mac[ip] != mac:
        print(f"[notification] possible ARP spoofing: {ip} was {ip_to_mac[ip]}, now claimed by {mac}")

    ip_to_mac[ip] = mac



def main():
    print(f"watching for ARP spoofing on {interface} press Ctrl-c to stop")
    sniff(iface=interface, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()