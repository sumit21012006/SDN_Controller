#!/usr/bin/env python3
import sys, time, argparse
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class SDNDDoSTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
        client1 = self.addHost('client1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        client2 = self.addHost('client2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        client3 = self.addHost('client3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        attacker1 = self.addHost('attacker1', ip='10.0.0.100/24', mac='00:00:00:00:00:A1')
        attacker2 = self.addHost('attacker2', ip='10.0.0.101/24', mac='00:00:00:00:00:A2')
        server1 = self.addHost('server1', ip='10.0.0.200/24', mac='00:00:00:00:00:FE')
        self.addLink(client1, s1)
        self.addLink(client2, s1)
        self.addLink(client3, s1)
        self.addLink(attacker1, s2)
        self.addLink(attacker2, s2)
        self.addLink(server1, s2)
        self.addLink(s1, s2)

def run_topology(controller_type='default', controller_ip='127.0.0.1', controller_port=6653, test_normal=False, test_attack=False):
    topo = SDNDDoSTopo()
    if controller_type == 'remote':
        info("*** Using Remote Controller (Ryu) at %s:%s\n" % (controller_ip, controller_port))
        controller = lambda name: RemoteController(name, ip=controller_ip, port=controller_port)
        net = Mininet(topo=topo, switch=OVSSwitch, controller=controller, link=TCLink, build=True)
    else:
        info("*** Using Standalone OVS Mode\n")
        net = Mininet(topo=topo, switch=OVSSwitch, controller=None, link=TCLink, build=True)
    net.start()
    for switch in net.switches:
        switch.cmd('ovs-vsctl set bridge %s protocols=OpenFlow13' % switch.name)
        if controller_type != 'remote':
            switch.cmd('ovs-ofctl -O OpenFlow13 add-flow %s "priority=0,actions=NORMAL"' % switch.name)
    if test_normal or test_attack:
        server1 = net.get('server1')
        client1 = net.get('client1')
        attacker1 = net.get('attacker1')
        info("-> Starting HTTP server on server1 (10.0.0.200:80)...\n")
        server1.cmd('python3 -m http.server 80 > /tmp/http_server.log 2>&1 &')
        time.sleep(1.0)
        info("-> Observing Baseline Warm-Up Period (15s)...\n")
        for s in range(15):
            client1.cmd('curl -s -o /dev/null http://10.0.0.200:80 &')
            time.sleep(1.0)
        info("-> Testing Legitimate Traffic...\n")
        net.pingAll()
        client1.cmd('curl -s -o /dev/null http://10.0.0.200:80')
        time.sleep(3.0)
        if test_attack:
            info("-> GENERATING CONTROLLED LAB ATTACK TRAFFIC (attacker1 -> server1)...\n")
            attacker1.cmd('hping3 --flood -S -p 80 10.0.0.200 > /dev/null 2>&1 &')
            for sec in range(10):
                time.sleep(1.0)
            attacker1.cmd('pkill -f hping3')
            info("-> Lab attack stopped.\n")
        server1.cmd('pkill -f "http.server"')
        net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    parser = argparse.ArgumentParser()
    parser.add_argument('--controller', choices=['default', 'remote'], default='default')
    parser.add_argument('--ip', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=6653)
    parser.add_argument('--test-normal', action='store_true')
    parser.add_argument('--test-attack', action='store_true')
    args = parser.parse_args()
    run_topology(controller_type=args.controller, controller_ip=args.ip, controller_port=args.port, test_normal=args.test_normal, test_attack=args.test_attack)
