#!/usr/bin/python

"""
Example network of Quagga routers
(QuaggaTopo + QuaggaService)
"""

import sys
import atexit

# patch isShellBuiltin
import mininet.util
import mininext.util
mininet.util.isShellBuiltin = mininext.util.isShellBuiltin
sys.modules['mininet.util'] = mininet.util

from mininet.util import dumpNodeConnections
from mininet.node import OVSController
from mininet.log import setLogLevel, info

from mininext.cli import CLI
from mininext.net import MiniNExT

from topo import QuaggaTopo

net = None

import time

def startNetwork():
    "instantiates a topo, then starts the network and prints debug information"

    info('** Creating Quagga network topology\n')
    topo = QuaggaTopo()

    info('** Starting the network\n')
    global net
    net = MiniNExT(topo, controller=OVSController)
    net.start()

    # assign IPs to interfaces.
    topo.setIP(net)

    # change IP forwarding variable to 1
    for host in net.hosts:
        host.cmd("echo '1' > /proc/sys/net/ipv4/ip_forward")

    # info('** Dumping host connections\n')
    # dumpNodeConnections(net.hosts)

    #info('** Testing network connectivity\n')
    #net.ping(net.hosts)

    #info('** Testing network connectivity\n')
    #net.ping(net.hosts)
    #info('** Dumping host processes\n')
    #for host in net.hosts:
     #   host.cmdPrint("ps aux")

    net.get('h1').cmdPrint("python /home/ping.py > /home/ping.log &")

    '''
    for i in range(1,50):
        #net.get('h1').cmdPrint("route")
        output = net.get('h1').cmd("ping -c 1 223.1.6.10")
        time.sleep(0.2)
        if output.find("unreachable") >= 0:
            continue
        else:
            print 'time it takes for h1 to be able to ping h2=', i*0.2, 's'
            break
    '''

    info('** Testing network connectivity\n')
    net.ping(net.hosts)

    info('** Running CLI\n')
    CLI(net)


def stopNetwork():
    "stops a network (only called on a forced cleanup)"

    if net is not None:
        info('** Tearing down Quagga network\n')
        net.stop()

if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()