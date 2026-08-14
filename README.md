# Network IDS

This is a python tool that will monitor network traffic and flag any suspicious
activity including port scans, ARP spoofing and rogue DHCP servers. This was built and tested on a home made GNS3 lab, with a simple web dashboard to show live alerts

## What it does

- **Packet sniffer** (`sniffer.py`) This will watch network traffic and print a summary 
of what it sees. This is the base everything else is built from.

- **Port scan detector** (`scan_detector.py`) If one device suddenly tries lots of different ports in a few seconds, that is the patter a port scan will leave and
this will catch it

- **ARP spoofing detector** (`arp_detector`) Every device on a network has an IP address
and a MAC address. This keeps track of which MAC goes with which IP and will raise an alert if it suddenly changes since this is a sign someone might be trying to impersonate another device

- **Rogue DHCP detector** (`dhcp_detector.py`) DHCP servers will hand out Ip addresses to a 
device when it joins the network. This flags any DHCP server that is not on an approved list.

- **Web dashboard** (`app.py`) A plain webpage that displays alerts from all three detectors

## How to set it up

```

pip install -r requirements.txt
```

You will also need [Npcap](https://npcap.com) installed . Run everything from a **administrator** terminal, or it will not have permission to capture traffic.

Before running anything, open  `list_interfaces.py` to find the name of your network adapter, then update the `interface` line near the top of each script to match it.

## How it was tested

While building this, i found a quirk in how windows captures traffic:
packets you send yourself from the same program that is alo listening usually do not get picked up by your own capture even though they genuinely reach their destination. This made it awkward to tes an attack and watch your own detector catch it if they are both running on the same machine.

For the port scan detector, there's a simple workaround — using a normal
scan tool (like Nmap's `-sT` option) instead of hand-crafted packets goes
through the operating system properly, so it gets picked up fine.

ARP spoofing and rogue DHCP don't have that workaround, since faking those
genuinely requires hand-crafted packets. So instead, I wrote a small test
for each one (`test_arp_detector_logic.py`, `test_dhcp_detector_logic.py`)
that checks the detection logic directly, without needing to actually
send anything over a real network. I also tried adding a separate "attacker"
device inside my GNS3 lab to get around this, but ran into a different
networking limitation there too — so I made the call to rely on these
tests instead of chasing that further.

## Helper scripts

- `list_interfaces.py` — lists your network adapters, to help you find the
  right one to use.
- `test_scan.py` — sends a real port scan at a target, to test
  `scan_detector.py`. It's set up for my specific lab, so you'd need to
  change the IP addresses inside it to use it elsewhere.

## Built with

Python, Scapy, Flask, GNS3, Nmap

