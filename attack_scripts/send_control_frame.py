"""
Send an ethernet control "pause" frame.

Usage: python send_control_frame.py <iface name>

Example iface name: eth0

"""
from socket import *
from sys import argv

#
# Ethernet Frame:
# [
#   [ Destination address, 6 bytes ]
#   [ Source address, 6 bytes      ]
#   [ Ethertype, 2 bytes           ]
#   [ Payload, 40 to 1500 bytes    ]
#   [ 32 bit CRC chcksum, 4 bytes  ]
# ]
#

# manually construct pause frame
interface = argv[1]
s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))
dst_addr = "\x01\x80\xc2\x00\x00\x01"
src_addr = "\x00\x0f\x5d\x30\x41\x50"
protocol = "\x00\x01"   # pause
time = "\xff\xff"
payload = "\x00"*42
checksum = "\x3f\xab\x2a\x6b"
ethertype = "\x88\x08"  # ethernet flow control
s.send(dst_addr+src_addr+ethertype+protocol+time+payload+checksum)
