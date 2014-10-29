from galatine_utils import send_arp
from base_module import base_module
from threading import Thread
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *


REQUEST = 1

class promiscuous_host_detector(base_module):
    def __init__(self, controldata):
        self.cd = controldata
        self.network = None

        # query matches all packets
        self.query = packets()
        self.query.register_callback(self.checker)

        # call inherited __init__
        super(promiscuous_host_detector,self).__init__(self.query)

        # set policy
        self.policy = flood()

        test_promiscuity_thread = Thread(target=self.test_promiscuity)
        test_promiscuity_thread.daemon = True
        test_promiscuity_thread.start()

    def test_promiscuity(self): 
        """Test if each host responds to ARP request sent to invalid MAC"""
        while True:
            INTERVAL = 10
            time.sleep(INTERVAL)
            print "Conducting promiscuity check..."
            now = time.time()

            # prepare to catch promiscuous hosts
            # to do this, we will send an ARP packet from a made up host to
            # each known host that has an INCORRECT dstmac address. If
            # the host responds, we know that it is listening on traffic that
            # is not intended for it, i.e. it is promiscuous.
            # ref. Sahai 01 "Detection of Promiscuous Nodes Using ARP Packets"
            wrong_mac = 'ff:ff:ff:ff:ff:fe'
            ips = self.cd.mac_of.keys() 
            # need at least 2 ips known to do this test
            if len(ips) < 2:
                print "Done."
                continue
            # pick random, unlikely mac
            key_mac = "77:77:77:77:77:77"
            self.policy = if_(match(dstmac=EthAddr(key_mac)), self.query, flood())

            # send out each physical port
            for loc in self.network.topology.egress_locations():
                switch  = loc.switch
                outport = loc.port_no
                dstmac = self.cd.get_port_to_mac(switch, outport)
                if not dstmac: 
                    # no mac associated with this port
                    continue
                dstip = next((k for k, v in self.cd.mac_of.items() if v == dstmac), None)
                if not dstip:
                    # no ip associated with this mac
                    continue

                # find valid IP address other than destination IP address
                key_ip = ips[0] if ips[0] != dstip else ips[1] 

                send_arp(REQUEST,self.network,switch,outport, key_ip, key_mac, dstip, wrong_mac)
    
            # wait for test to complete and revert policy
            time.sleep(1)
            self.policy = flood()
            print "Done."

    def checker(self, pkt):
        print "Observation: host %s is promiscuous" % pkt['srcmac']
        self.block_port(pkt['inport'], pkt['switch'])

