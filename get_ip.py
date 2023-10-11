import fcntl
import socket
import struct
from netifaces import AF_INET, ifaddresses

def get_ip_linux(interface: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packed_iface = struct.pack('256s', interface.encode('utf_8'))
    packed_addr = fcntl.ioctl(sock.fileno(), 0x8915, packed_iface)[20:24]
    return socket.inet_ntoa(packed_addr)

def get_ip_cross(interface: str) -> str:
    return ifaddresses(interface)[AF_INET][0]['addr']
