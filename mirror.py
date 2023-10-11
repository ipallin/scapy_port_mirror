import sys
from scapy.all import *
import time
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from get_ip import get_ip_cross

# imputs
intinterface = str(input("Clone the traffic from: "))
extinterface = str(input("Send the mirrored trafic trough: "))
ip_dst = str(input("Destination IP: "))
interval = int(input("Time interval between packets in seconds: "))
ip_src = get_ip_cross(extinterface)

# sniffer
def capture_and_send(pkt):
    pkt[IP].src = ip_src
    pkt[IP].dst = ip_dst
    sendp(pkt, iface=extinterface)

sniff(iface=intinterface, prn=capture_and_send)
