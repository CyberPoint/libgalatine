Galatine
=======

Galatine is a project for detecting layer 2 attacks and automatically
remediating them from within an SDN controller. It is written in the
Pyretic language.

For information on the Pyretic project visit www.frenetic-lang.org/pyretic. It is
recommended that you run Pyretic in the Pyretic VM, which can be found at that
website.

In the modules/ directory, there are several elements of a Pyretic controller
that can be combined to add various security aspects to the network. The
main module is galatine_controller.py. To run this, you must add the modules 
in this directory to the pyretic/modules directory in the pyretic repo (another
option is to create a symbolic link). Once that is done, navigate to the pyretic
directory and execute the command:

	pyretic.py -m r0 pyretic.modules.galatine_controller


Config
------
By default, galatine provides protection against the following:

* ARP spoofing
* MAC flooding
* DoSing the controller
* Ethernet control frames   

To configure this, edit the security_measures variable in galatine_controller.py
(simply comment out any protections you do not wish to use).

By default, galatine only provides one option for remediation, namely cutting
off the offending host(s) from the network. In future versions there will be
more than one option, and remediation strategy will be configurable.

Environment
-----------
The easiest environment in which to experiment with this controller is
mininet.
 Recommended command:

	sudo mn --controller remote --topo single,4

Please note that mininet does not work with the promiscuous mode detection. This is
due to the fact that mininet hosts are always in promiscuous mode.

Testing
-------
You can run the various scripts in attack_scripts to test out the controller.
The example mininet command would be: 

	h1 arp_reply_spoof.py -v h2 -r h3

This will attempt to establish a MitM attack from h1 between h2 and h3.
