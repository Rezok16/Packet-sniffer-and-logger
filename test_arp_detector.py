from scapy.all import Ether, ARP
 
# Same detection logic as arp_detector.py
ip_to_mac = {}
 
 
def handle_packet(packet):
    if ARP not in packet:
        return
 
    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc
 
    if ip == "0.0.0.0":
        return
 
    if ip in ip_to_mac and ip_to_mac[ip] != mac:
        print(f"[notification] possible ARP spoofing: {ip} was {ip_to_mac[ip]}, now claimed by {mac}")
 
    ip_to_mac[ip] = mac
 
 
# Step 1: simulate R1's real, legitimate ARP announcement.
real_packet = Ether() / ARP(op=2, psrc="192.168.138.10", hwsrc="0c:98:41:17:00:00")
handle_packet(real_packet)
print("Recorded real R1 mapping — no alert expected above this line.")
print()
 
# Step 2: simulate an attacker claiming to BE R1, with a different MAC.
spoofed_packet = Ether() / ARP(op=2, psrc="192.168.138.10", hwsrc="de:ad:be:ef:00:01")
handle_packet(spoofed_packet)
print()
print("Sent spoofed mapping — the [notification] line above should have fired.")