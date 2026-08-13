from scapy.all import Ether, IP, UDP, BOOTP, DHCP

known_servers = {"192.168.138.10"}

def handle_packet(packet):
    if DHCP not in packet:
        return

    msg_type = next((v for k, v in packet[DHCP].options if k == "message-type"), None)

    if msg_type != "offer":
        return
    
    server_ip = packet[IP].src
    server_mac = packet[Ether].src

    if server_ip not in known_servers:
        print(f"[notification] possible rouge DHCP server: {server_ip} ({server_mac}) sent a DHCP offer")
    else:
        print(f"[debug] DHCP offer from a known server {server_ip}")


legitimate_offer = (
    Ether(src="0c:98:41:17:00:00")
    / IP(src="192.168.138.10", dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(op=2, yiaddr="192.168.138.50")
    / DHCP(options=[("message-type", "offer"), "end"])
)
handle_packet(legitimate_offer)
print("sent legitimate offer from R1 no alert expected above.")
print()

rouge_offer = (
    Ether(src="de:ad:be:ef:00:02")
    / IP(src="192.168.138.99", dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(op=2, yiaddr="192.168.138.66")
    / DHCP(options=[("message-type", "offer"), "end"])
)
handle_packet(rouge_offer)
print()
print("sent rogue offer from an unkown server - the [notification] line should fire")
