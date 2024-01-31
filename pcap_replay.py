#!/usr/bin/python
import time
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, send
from scapy.layers.inet import IP

parser = argparse.ArgumentParser(description='PCAP Replay')
parser.add_argument('filename', nargs='?', default='replay.pcap', help='PCAP file to replay')
parser.add_argument('--loop', type=int, default=1, help='Number of times to loop the replay')
parser.add_argument('--src-ip', type=str, help='Source IP address')
parser.add_argument('--dst-ip', type=str, help='Destination IP address')


args = parser.parse_args()

filename = args.filename
loop = args.loop

pkts = rdpcap(filename)
clk = pkts[0].time

while loop > 0:
    for p in pkts:
        if not p.haslayer(IP):
            continue
        time.sleep(int(p.time) - int(clk))
        clk = p.time
        if args.src_ip:
            p[IP].src = args.src_ip
        if args.dst_ip:
            p[IP].dst = args.dst_ip        
        send(p[IP], iface="WiFi", verbose=False)
    loop -= 1
