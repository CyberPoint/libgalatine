"""
This module implements an ARP spoofing detector in the Pyretic language.

@author: ccabot
@author: zmiller
July 2014

The strategy: 

Route all ARP packets through the controller (this can be optimized later).
Record a table of IP-MAC address pairings. In the event that a packet is 
detected that conflicts with this table, attempt to determine if the IP address
change is legitimate. To do this, if the suspicious packet is a reply,
ask all hosts who has the suspicious IP address. If two or more hosts say 
that they do, confirm spoofing and cut those hosts off the network. If the
suspicious packet is a response, ask the suspicious host if he has the IP 
address he just announced. If he doesn't reply, he is being inconsistent,
so cut him off the network.

"""
import collections
import threading
from galatine_utils import send_arp, bcolors, RESPONSE, REQUEST, PortInfo
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from base_module import base_module

ARP = match(ethtype=ARP_TYPE)

class arp_spoofing_detector(base_module):
    """Detect ARP spoofing"""
    def __init__(self, controldata):
        self.cd = controldata
        self.network = None

        # run check on each arp packet
        self.query = packets()
        self.query.register_callback(self.handle_arp)

        super(arp_spoofing_detector, self).__init__(self.query)

        # set policy to check for ARP spoofing if the current packet is an ARP packet
        self.policy = if_(ARP, self.query + identity(), identity())

        self.under_investigation = set()


    def handle_arp(self, pkt):
        """Process an ARP packet""" 
        switch = pkt['switch']
        inport = pkt['inport']
        srcip  = pkt['srcip']
        srcmac = pkt['srcmac']
        dstip  = pkt['dstip']
        dstmac = pkt['dstmac']
        opcode = pkt['protocol']

        # ignore packets from 0.0.0.0 
        if str(srcip) == '0.0.0.0':
            return

        # do first check
        if self.under_investigation == set():
            if self.cd.get_mac_of(srcip):
                # check for violation of what we've been seeing
                if self.cd.get_mac_of(srcip) != srcmac:
                    self.under_investigation.add(srcip)
                    print bcolors.WARNING + "Observation: %s said he was %s when we have on record that %s is %s" % (
                        srcmac, srcip, self.cd.get_mac_of(srcip), srcip) + bcolors.ENDC
                    
                    if opcode == RESPONSE:
                        self.init_reply_doublecheck(pkt)
                    else:
                        self.init_request_doublecheck(pkt)
                        
            else:
                # learn mac
                self.cd.set_mac_of(srcip, srcmac)  

    def init_reply_doublecheck(self, pkt):
        """Ask the network who has each IP address. Does more than one host respond?"""
        print "Initiating doublecheck. Asking who has each IP address..."
        self.reply_doublecheck_dict = {}
        ips = self.cd.mac_of.keys()
        # sanity
        if len(ips) < 2: 
            return
        for ip in ips:
            if self.network is None:
                print "self.network is None, will error out..."

            # assemble ARP request params
            xswitch = pkt["switch"]
            xinport = pkt["inport"]
            # find valid IP address other than destination IP address
            srcip   = ips[0] if ips[0] != ip else ips[1] 
            srcmac  = self.cd.get_mac_of(srcip)
            dstmac  = "ff:ff:ff:ff:ff:ff"
            dstip   = ip

            # send out each physical port
            self.query.register_callback(self.log_reply_doublecheck)
            for loc in self.network.topology.egress_locations():
                switch  = loc.switch
                outport = loc.port_no
                send_arp(REQUEST,self.network,switch,outport,srcip,srcmac,dstip,dstmac)
           
        # in one second, check
        self.check_thread = threading.Thread(target=self.check_reply_doublecheck, args=(pkt['srcip'],))
        self.check_thread.daemon = True
        self.check_thread.start()
        return

    def log_reply_doublecheck(self, pkt):
        """Gather responses"""
        switch = pkt['switch']
        srcip = pkt['srcip']
        inport = pkt['inport']

        # do nothing if not egress port
        if inport not in [loc.port_no for loc in self.network.topology.egress_locations(switch)]:
            return 

        if pkt["ethtype"] == ARP_TYPE and pkt["protocol"] == RESPONSE:
            try:
                self.reply_doublecheck_dict[srcip]["members"].add(pkt["srcmac"])
                self.reply_doublecheck_dict[srcip]["inports"].add(PortInfo(switch, inport))
                self.reply_doublecheck_dict[srcip]["count"] = len(
                    self.reply_doublecheck_dict[srcip]["members"])
            except:
                self.reply_doublecheck_dict[srcip] = {
                    "count": 1, 
                    "inports": set([PortInfo(switch, inport)]), 
                    "members": set([pkt["srcmac"]])
                }

    def check_reply_doublecheck(self, srcip):
        """Check for overlaps, remediate, and clean up"""
        time.sleep(1)   # wait one second for responses
        d = self.reply_doublecheck_dict
        for key in d.keys():
            if d[key]["count"] > 1:
                print bcolors.WARNING + "Observation: two hosts claim they are %s" % key + bcolors.ENDC
                for switch_port in d[key]["inports"]:
                    self.block_port(switch_port.port, switch_port.switch)
            else: 
                # update table
                self.cd.set_mac_of(key, d[key]["members"].copy().pop())

        # remove logging callback
        # you may be wondering... what is self.query.fb.callbacks? basically,
        # it's where "register_callbacks" stores the functions. since there's
        # no "unregister_callback" function, I had to hack it and manually
        # delete it once it's no longer needed
        try:
            while True:
                self.query.fb.callbacks.remove(self.log_reply_doublecheck)
                #print "removing reply doublecheck log"
        except ValueError:
            pass
        self.under_investigation.remove(srcip)
        return

    def init_request_doublecheck(self, pkt):
        """Send ARP request to suspicious host."""

        # store suspect info
        self.suspect = (pkt["srcip"], pkt["srcmac"], pkt["inport"], pkt["switch"])
        self.suspect_guilt = True
        self.query.register_callback(self.log_request_doublecheck)

        # assemble ARP request params
        switch = pkt["switch"]
        outport = pkt["inport"]
        srcip   = pkt['dstip']
        srcmac  = self.cd.get_mac_of(srcip)
        dstmac  = "ff:ff:ff:ff:ff:ff"
        dstip   = pkt["srcip"]
        # send request
        send_arp(REQUEST,self.network,switch,outport,srcip,srcmac,dstip,dstmac)

        # issue thread to check
        self.check_thread2 = threading.Thread(target=self.check_request_doublecheck)
        self.check_thread2.daemon = True
        self.check_thread2.start()
        return

    def log_request_doublecheck(self, pkt):
        """Check if the suspicious host replies in accord with its request"""
        if pkt["ethtype"] == ARP_TYPE and pkt["protocol"] == RESPONSE: 
            if (pkt["srcip"], pkt["srcmac"]) == self.suspect[:2]:
                print "Host %s found not guilty" % pkt["srcmac"]
                self.suspect_guilt = False
                self.cd.set_mac_of(pkt["srcip"], pkt["srcmac"])
        
    def check_request_doublecheck(self):
        """Check for inconsistency, remediate, and clean up"""
        time.sleep(0.5)     # wait for response
        if self.suspect_guilt:
            print "Observation: host %s is acting inconsistently" % self.suspect[1]
            self.block_port(self.suspect[2], self.suspect[3])
        # if suspect answers consistently, recall that
        # that will trip the arp reply spoofing detector

        # clean up
        try:
            while True:
                self.query.fb.callbacks.remove(self.log_request_doublecheck)
                print "removing reply doublecheck log"
        except ValueError:
            pass

def main():
    return arp_spoofing_detector() 

