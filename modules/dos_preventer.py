"""
Prevent hosts attempting to DoS the switch or the controller

"""
from time import sleep
from threading import Thread
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from base_module import base_module

class dos_preventer(base_module):
    def __init__(self, controldata):
        self.cd = controldata
        self.foreign_host_count = {}
        self.network = None

        # run check on each packet with new MAC address
        self.query = packets(limit=1, group_by=['dstmac'])
        self.query.register_callback(self.monitor_foreign_host)

        # call inherited __init__
        super(dos_preventer,self).__init__(self.query)

        # set policy
        self.policy = self.query + flood()

        # set thread to clear counts every day
        self.mac_count_reset_thread = Thread(target=self.clear_mac_count)
        self.mac_count_reset_thread.daemon = True
        self.mac_count_reset_thread.start()

    def monitor_foreign_host(self, pkt):
        """Record which inport is contacting a foreign MAC"""
        inport = pkt['inport']
        switch = pkt['switch']
        if switch not in self.foreign_host_count.keys():
            self.foreign_host_count[switch] = {}
        try:
            self.foreign_host_count[switch][inport] += 1

            # do we need to remediate?
            MAX_MACS = 100
            if self.foreign_host_count[switch][inport] == MAX_MACS:
                print "Observation: port %s on switch %s has attempted to " \
                "contact 100 different MAC " \
                "addresses in the past 60 seconds." \
                " It is likely attempting to DoS the controller." % (inport, switch) 
                self.block_port(inport, switch)
        except KeyError:
            self.foreign_host_count[switch][inport] = 1

    def clear_mac_count(self):
        """Periodically, reset all counts to 0"""
        ONE_MINUTE = 60
        while True:
            # sleep 
            sleep(ONE_MINUTE)
            # reset all counts to 0
            for k in self.foreign_host_count.keys():
                self.foreign_host_count[k] = 0



        
