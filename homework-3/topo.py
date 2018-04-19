"""
Example topology of Quagga routers
"""

import inspect
import os
from mininext.topo import Topo
from mininext.services.quagga import QuaggaService

from collections import namedtuple

QuaggaHost = namedtuple("QuaggaHost", "name ip")
net = None


class QuaggaTopo(Topo):

    "Creates a topology of Quagga routers"

    def __init__(self):
        """Initialize a Quagga topology with 5 routers, configure their IP
           addresses, loop back interfaces, and paths to their private
           configuration directories."""
        Topo.__init__(self)

        # Directory where this file / script is located"
        selfPath = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))  # script directory

        # Initialize a service helper for Quagga with default options
        quaggaSvc = QuaggaService(autoStop=False)

        # Path configurations for mounts
        quaggaBaseConfigPath = selfPath + '/configs/'

        # List of Quagga host configs
        quaggaHosts = []
        quaggaHosts.append(QuaggaHost(name='r1', ip='223.1.1.1/24'))
        quaggaHosts.append(QuaggaHost(name='r2', ip='223.1.2.1/24'))
        quaggaHosts.append(QuaggaHost(name='r3', ip='223.1.1.2/24'))
        quaggaHosts.append(QuaggaHost(name='r4', ip='223.1.3.2/24'))
        quaggaHosts.append(QuaggaHost(name='h1', ip='223.1.5.10/24'))
        quaggaHosts.append(QuaggaHost(name='h2', ip='223.1.6.10/24'))

        quaggas = {}

        # Setup each Quagga router
        for host in quaggaHosts:

            # Create an instance of a host, called a quaggaContainer
            quaggaContainer = self.addHost(name=host.name,
                                           ip=host.ip,
                                           hostname=host.name,
                                           privateLogDir=True,
                                           privateRunDir=True,
                                           inMountNamespace=True,
                                           inPIDNamespace=True,
                                           inUTSNamespace=True)

            # Configure and setup the Quagga service for this node
            quaggaSvcConfig = {'quaggaConfigPath': quaggaBaseConfigPath + host.name}
            self.addNodeService(node=host.name, service=quaggaSvc, nodeConfig=quaggaSvcConfig)

            quaggas[host.name] = quaggaContainer

        # Add the links
        self.addLink(quaggas['h1'], quaggas['r1'])  # h1-eth0 : r1-eth0
        self.addLink(quaggas['h2'], quaggas['r4'])  # h2-eth0 : r4-eth0
        self.addLink(quaggas['r1'], quaggas['r2'])  # r1-eth1 : r2-eth0
        self.addLink(quaggas['r3'], quaggas['r4'])  # r3-eth0 : r4-eth1
        self.addLink(quaggas['r1'], quaggas['r3'])  # r1-eth2 : r3-eth1
        self.addLink(quaggas['r2'], quaggas['r4'])  # r2-eth1 : r4-eth2


    def setIP(self, net):
        r1 = net.get('r1')
        r1.setIP(intf='r1-eth0', ip='223.1.5.1/24')
        r1.setIP(intf='r1-eth1', ip='223.1.2.2/24')
        r1.setIP(intf='r1-eth2', ip='223.1.1.1/24')

        r2 = net.get('r2')
        r2.setIP(intf='r2-eth0', ip='223.1.2.1/24')
        r2.setIP(intf='r2-eth1', ip='223.1.4.2/24')

        r3 = net.get('r3')
        r3.setIP(intf='r3-eth0', ip='223.1.3.1/24')
        r3.setIP(intf='r3-eth1', ip='223.1.1.2/24')

        r4 = net.get('r4')
        r4.setIP(intf='r4-eth0', ip='223.1.6.1/24')
        r4.setIP(intf='r4-eth1', ip='223.1.3.2/24')
        r4.setIP(intf='r4-eth2', ip='223.1.4.1/24')


