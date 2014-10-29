"""
Global variables that all controller modules share.

"""
class ControlData(object): 
    """Shared data across galatine modules"""

    def __init__(self):
        self.mac_of = {}
        """dict of ip: mac pairs"""

        self.port_to_mac = {}
        """dict of port: mac pairs"""

    def get_port_to_mac(self, switch, port):
        if switch not in self.port_to_mac: 
            return None
        if port not in self.port_to_mac[switch]:
            return None
        return self.port_to_mac[switch][port]

    def get_mac_of(self, ip):
        if ip not in self.mac_of: 
            return None
        return self.mac_of[ip]

    def set_mac_of(self, ip, mac):
        print "setting %s <--> %s" % (ip, mac)
        self.mac_of[ip] = mac

    def set_port_to_mac(self, switch, port, mac):
        if switch not in self.port_to_mac.keys():
            self.port_to_mac[switch] = {}
        self.port_to_mac[switch][port] = mac

