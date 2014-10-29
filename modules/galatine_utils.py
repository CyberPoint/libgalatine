from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

VERBOSE_LEVEL = 0
RESPONSE = 2
REQUEST = 1

class PortInfo(object):
    def __init__(self, switch, port):
        self.switch = switch
        self.port = port

class bcolors:
    """Use escape characters for colored output in terminal""" 
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def send_arp(msg_type,network,switch,outport,srcip,srcmac,dstip,dstmac):
    """Construct an arp packet from scratch and send"""
    rp = Packet()
    rp = rp.modify(protocol=msg_type)
    rp = rp.modify(ethtype=ARP_TYPE)
    rp = rp.modify(switch=switch)
    rp = rp.modify(inport=-1)
    rp = rp.modify(outport=outport)
    rp = rp.modify(srcip=srcip)
    rp = rp.modify(srcmac=srcmac)
    rp = rp.modify(dstip=dstip)
    rp = rp.modify(dstmac=dstmac)
    rp = rp.modify(raw='')

    if VERBOSE_LEVEL > 0:
        if msg_type == RESPONSE:
            print "--------- INJECTING RESPONSE ON %d[%d] FOR %s TO %s -----------" % (switch,outport,srcip,dstip)
        if msg_type == REQUEST:
            print "--------- INJECTING REQUEST ON %d[%d] FOR %s FROM %s -----------" % (switch,outport,dstip,srcip)
        if VERBOSE_LEVEL > 1:
            print rp

    network.inject_packet(rp)
