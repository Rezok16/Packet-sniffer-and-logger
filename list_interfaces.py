from scapy.arch.windows import get_windows_if_list

for iface in get_windows_if_list():
    print(f"name: {iface['name']}")
    print(f"description: {iface['description']}")
    print(f"ips: {iface.get('ips')}")