from scapy.all import *

def sniff_icmp(interface):
    sniff(filter="icmp", iface=interface, prn=lambda x: hexdump(x))

# Replace "wlan0" with your WiFi interface name
sniff_icmp("WiFi")
