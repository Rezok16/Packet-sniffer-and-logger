from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

interface = "VMware Network Adapter VMnet1"

time_window = 10
port_threshold = 10

recent_activity = defaultdict(list)
alerted = set()

def prune_old(entries, now):
    return[(t,p) for (t,p) in entries if now - t <= time_window]

    
def handle_packet(packet):
    if IP not in packet or TCP not in packet:
            return


    if packet[TCP].flags != "S":
         return

    src = packet[IP].src
    dport = packet[TCP].dport
    now = time.time()

    print(f"[debug] SYN seen: {src} port {dport}")

    recent_activity[src] = prune_old(recent_activity[src], now)
    recent_activity[src].append((now, dport))

    distinct_ports = {p for (_, p) in recent_activity[src]}

    if len(distinct_ports) >= port_threshold and src not in alerted:
         print(f"[notification] possible port scan from {src} -")
         print(f"{len(distinct_ports)} distinct ports in {time_window}s")
         alerted.add(src)
    elif len(distinct_ports) < port_threshold and src not in alerted:
         alerted.discard(src)     




def main():
    print(f"Watching for port scans on {interface} press Ctrl-c to stop")
    sniff(iface=interface, prn=handle_packet, store=False)

if __name__ == "__main__":
    main()