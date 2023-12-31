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
ip_src = get_ip_cross(extinterface)

# sniffer
def capture_and_send(pkt):
    pkt = pkt[IP]
    del(pkt.chksum)
    del(pkt[TCP].chksum)
    pkt.src = ip_src
    pkt.dst = ip_dst
    print(pkt.show())
    send(pkt, iface=extinterface)

sniff(iface=intinterface, prn=capture_and_send)
