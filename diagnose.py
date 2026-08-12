from scapy.all import conf, getmacbyip
 
iface = "VMware Network Adapter VMnet1"
conf.iface = iface
conf.route.add(net="192.168.30.0/24", gw="192.168.138.10", dev=iface)
 
print("Scapy's route resolution for 192.168.30.2:")
print(conf.route.route("192.168.30.2"))
print()
 
print("Trying to resolve gateway MAC for 192.168.138.10...")
mac = getmacbyip("192.168.138.10")
print(f"Result: {mac}")