import sys
from scapy.all import *
import time
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from get_ip import get_ip_cross

# imputs
dstinterface = str(input("Enter the interface to clone the packets: "))
orginterface = str(input("Enter the interface to send the packets: "))
ip_dst = str(input("Enter the destination IP: "))
interval = int(input("Enter the time interval between packets in seconds (0 for none): "))
ip_src = get_ip_cross(orginterface)

# sniffer
pkts = open_live(interface, 65535, 1, 100)

# loop
for pkt in pkts:
    del(pkt.chksum)
	pkt = pkt[IP]
    pkt.src= ip_src
    pkt.dst= ip_dst
    #print(pkt.show())
    sendp(packets_list, iface=interface, inter=interval)
