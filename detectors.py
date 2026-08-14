from scapy.all import sniff, IP, TCP, ARP, DHCP, Ether
from collections import defaultdict
import time
import threading

interface = "VMware Network Adapter VMnet1"

time_window = 10
port_threshold = 10
known_dhcp_servers = {"192.168.138.10"}

alerts = []
alert_lock = threading.Lock()

recent_activity = defaultdict(list)
scan_alert = set()
ip_to_mac = {}

def add_alert(message):
    with alert_lock:
        alerts.append({"time": time.strftime("%H:%M:%S"), "message": message})
        if len(alerts) > 200:
            del alerts[0]


def check_port_scan(packet):
    if TCP not in packet or packet[TCP].flags != "S":
        return
    src = packet[IP].src
    dport = packet[TCP].dport
    now = time.time()
    recent_activity[src] = [(t, p) for (t, p) in recent_activity[src] if now -t <= time_window]
    recent_activity[src].append((now, dport))
    distinct_ports = {p for (_, p) in recent_activity[src]}
    if len(distinct_ports) >= port_threshold and src not in scan_alert:
        add_alert(f"Possible port scan from {src} - {len(distinct_ports)} ports in {time_window}s")
        scan_alert.add(src)
    elif len(distinct_ports) < port_threshold and src in scan_alert:
        scan_alert.discard(src)

def check_arp_spoof(packet):
    if ARP not in packet:
        return
    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc
    if ip == "0.0.0.0":
        return
    if ip in ip_to_mac and ip_to_mac[ip] != mac:
        add_alert(f"Possible ARP spoofing: {ip} was {ip_to_mac[ip]}, now claimed by {mac}")
        ip_to_mac[ip] = mac

def check_rouge_dhcp(packet):
    if DHCP not in packet:
        return
    msg_type = next((v for k, v in packet[DHCP].options if k == "message-type"), None)

    if msg_type != 2:
        return
    server_ip = packet[IP].src
    server_mac = packet[Ether].src
    if server_ip not in known_dhcp_servers:
        add_alert(f"Possible rouge DHCP server: {server_ip} ({server_mac})")

def handle_packet(packet):
    check_port_scan(packet)
    check_arp_spoof(packet)
    check_rouge_dhcp(packet)


def start_sniffing():
    sniff(iface=interface, prn=handle_packet, store=False)

def start_background():
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()