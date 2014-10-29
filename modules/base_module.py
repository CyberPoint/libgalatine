"""
Base module (for shared methods and inheritances among modules).

"""
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from galatine_utils import bcolors

class base_module(DynamicPolicy):

    def set_network(self, network):
        """Including this method results in the network getting set"""
        self.network = network

    def block_port(self, port, switch):
        """Don't allow any traffic to or from a port"""
        # make sure to only block the host from the attached switches 
        if port in [loc.port_no for loc in self.network.topology.egress_locations(switch)]:
            print bcolors.FAIL + "Remediation: blocking port %s on "\
                "switch %s" % (port, switch) + bcolors.ENDC
            self.policy = if_((match(inport=port, switch=switch) | 
                match(outport=port, switch=switch)), drop, self.policy)
