#!/usr/bin/python
from scapy.all import *
import time, sys
pkts = rdpcap(sys.argv[1])
clk = pkts[0].time
for p in pkts:
    time.sleep(p.time - clk)
    clk = p.time
    sendp(p)