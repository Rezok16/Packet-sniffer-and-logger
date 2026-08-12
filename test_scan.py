from scapy.all import IP, TCP, sendp, conf
import time

iface = "VMware Network Adapter VMnet1"

conf.iface = iface

gateway_mac = "0c-98-41-17-00-00"


target = "192.168.30.2" #change to test device you want to test
start_port = 1
end_port = 30

for port in range(start_port, end_port + 1):
    pkt = IP(dst=target) / TCP(dport = port, flags="S")
    sendp(pkt,iface=iface, verbose=False)
    time.sleep(0.05)

print(f"SYN to ports {start_port}-{end_port} on {target}")