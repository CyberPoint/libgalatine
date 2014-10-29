"""
Detect control frames, which are somewhat obsolete flow-control
mechanisms. They can generally be considered suspicious.

"""
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from base_module import base_module

# flow control frames have this ethtype
FLOW_CONTROL = 0x8808

class control_frames_detector(base_module):
    def __init__(self, controldata):
        self.cd = controldata

        # run check on each packet with new MAC address
        self.query = packets()
        self.query.register_callback(self.monitor_ethtype)

        # call inherited __init__
        super(control_frames_detector,self).__init__(self.query)

        # set policy
        self.policy = flood() + (match(ethtype=FLOW_CONTROL) >> self.query)

    def monitor_ethtype(self, pkt):
        """Look for hosts emitting suspicious frames"""
        print "Observation: host %s sent an ethernet flow control frame. "\
        "This is suspicious. The frame was:\n %s" % (pkt['srcmac'], pkt)
        self.block_port(pkt['inport'], pkt['switch'])
