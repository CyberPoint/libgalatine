"""
Detect MAC Flooding

"""
from time import sleep
from threading import Thread
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from base_module import base_module

class mac_flooding_detector(base_module):
    def __init__(self, controldata):
        self.cd = controldata
        self.port_macs_count = {}
        self.network = None

        # run check on each packet with new MAC address
        self.query = packets(limit=1, group_by=['srcmac'])
        self.query.register_callback(self.monitor_mac)

        # call inherited __init__
        super(mac_flooding_detector,self).__init__(self.query)

        # set policy
        self.policy = self.query + flood()

        # set thread to clear counts every day
        self.mac_count_reset_thread = Thread(target=self.clear_mac_count)
        self.mac_count_reset_thread.daemon = True
        self.mac_count_reset_thread.start()

    def monitor_mac(self, pkt):
        """Record which inport announced this new MAC"""
        inport = pkt['inport']
        switch = pkt['switch']
        if switch not in self.port_macs_count.keys():
            self.port_macs_count[switch] = {}
        try:
            self.port_macs_count[switch][inport] += 1

            # do we need to remediate?
            MAX_MACS = 100
            if self.port_macs_count[switch][inport] == MAX_MACS:
                print "Observation: port %s on switch %s has announced "\
                "100 different MAC addresses in " \
                "the past 24 hours. It is likely attempting"\
                " a MAC flooding attack." % (inport, switch)
                self.block_port(inport, switch)
        except KeyError:
            self.port_macs_count[switch][inport] = 1

    def clear_mac_count(self):
        """Once a day, reset all counts to 0"""
        ONE_DAY = 86400
        while True:
            # sleep 
            sleep(ONE_DAY)
            # reset all counts to 0
            for k in self.port_macs_count.keys():
                self.port_macs_count[k] = 0



        
