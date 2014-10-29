"""
Main Galatine controller module.

"""
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

from mac_learner import mac_learner
from arp_spoofing_detector import arp_spoofing_detector
from mac_flooding_detector import mac_flooding_detector
from dos_preventer import dos_preventer
from control_frames_detector import control_frames_detector
from promiscuous_host_detector import promiscuous_host_detector

from galatine_globals import ControlData

# config
initial_policy = mac_learner
security_measures = [
    dos_preventer,
    control_frames_detector, 
    mac_flooding_detector, 
    arp_spoofing_detector,
    promiscuous_host_detector
]

def main(): 
    """Combine our modules to yield our final policy"""

    # instantiate object to hold shared data across modules
    cd = ControlData()

    policies = [initial_policy(cd)] + map(lambda x: x(cd), security_measures)    
    return sequential(policies) 

