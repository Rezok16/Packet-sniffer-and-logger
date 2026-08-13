from scapy.all import sniff, DHCP, IP, Ether

interface = "VMware Network Adapter VMnet1"

known_servers = {"192.168.138.10"}

def handle_packet(packet):
    if DHCP not in packet:
        return


    server_ip = packet[IP].src
    server_mac = packet[Ether].src

    if server_ip not in known_servers:
        print(f"[notification] possible rouge DHCP server: {server_ip} ({server_mac}) sent a DHCP Offer")
    else:
        print(f"[debug] DHCP offer from a known server {server_ip}")





def main():
    print("watching for rouge DHCP servers on {interface} press Ctrl-c to stop")
    sniff(iface=interface, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()