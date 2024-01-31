import pyshark

def print_ping_origin(packet):
    if 'ICMP' in packet:
        print(packet['IP'].get_field('src') + " -> " + packet['IP'].get_field('dst'))
    if 'HTTP' in packet:
        print("HTTP!")

capture = pyshark.LiveCapture(interface="WiFi")
capture.sniff(packet_count=10, timeout=10)
capture.apply_on_packets(print_ping_origin) 
