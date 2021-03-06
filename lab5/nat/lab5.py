#!/usr/bin/python

"""
Start up a Simple topology for CS144
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE, check_call

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

class CS144Topo( Topo ):
    "CS 144 Lab 5 Topology"

    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        server1 = self.addHost( 'server1' )
        nat = self.addSwitch( 'sw0' )
        client = self.addHost('client', inNamespace=False)
        for h in client, server1:
            self.addLink( h, nat )


class CS144Controller( Controller ):
    "Controller for CS144 Multiple IP Bridge"

    def __init__( self, name, inNamespace=False, command='controller',
                 cargs='-v ptcp:%d', cdir=None, ip="127.0.0.1",
                 port=6633, **params ):
        """command: controller command name
           cargs: controller command arguments
           cdir: director to cd to before running controller
           ip: IP address for controller
           port: port for controller to listen at
           params: other params passed to Node.__init__()"""
        Controller.__init__( self, name, ip=ip, port=port, **params)

    def start( self ):
        """Start <controller> <args> on controller.
            Log to /tmp/cN.log"""
        pathCheck( self.command )
        cout = '/tmp/' + self.name + '.log'
        if self.cdir is not None:
            self.cmd( 'cd ' + self.cdir )
        self.cmd( self.command, self.cargs % self.port, '>&', cout, '&' )

    def stop( self ):
        "Stop controller."
        self.cmd( 'kill %' + self.command )
        self.terminate()


def startsshd( host ):
    "Start sshd on host"
    stopsshd()
    info( '*** Starting sshd\n' )
    name, intf, ip = host.name, host.defaultIntf(), host.IP()
    banner = '/tmp/%s.banner' % name
    host.cmd( 'echo "Welcome to %s at %s" >  %s' % ( name, ip, banner ) )
    host.cmd( '/usr/sbin/sshd -o "Banner %s"' % banner, '-o "UseDNS no"' )
    info( '***', host.name, 'is running sshd on', intf, 'at', ip, '\n' )


def stopsshd():
    "Stop *all* sshd processes with a custom banner"
    info( '*** Shutting down stale sshd/Banner processes ',
          quietRun( "pkill -9 -f Banner" ), '\n' )


def startserver( host, client ):
    "Start grading server"
    info( '*** Starting Grading Server\n' )
    host.cmd( 'cd ./grading_server/; nohup python2.7 ./server.pyc &')
    client.cmd( 'cd ./grading_server/; rm result.txt; nohup python2.7 ./reader.pyc > result.txt &' )


def stopserver():
    "Stop grading servers"
    info( '*** Shutting down stale SimpleHTTPServers',
          quietRun( "pkill -9 -f SimpleHTTPServer" ), '\n' )
    info( '*** Shutting down stale webservers',
          quietRun( "pkill -9 -f server.pyc" ), '\n' )
    info( '', quietRun( "pkill -9 -f reader.pyc" ), '\n' )

def set_default_route(host):
    info('*** setting default gateway of host %s\n' % host.name)
    if(host.name == 'server1'):
        routerip = IP_SETTING['sw0-eth2']
    elif(host.name == 'server2'):
        routerip = IP_SETTING['sw0-eth2']
    elif(host.name == 'client'):
        routerip = IP_SETTING['sw0-eth1']
    print host.name, routerip
    host.cmd('route add %s/32 dev %s-eth0' % (routerip, host.name))
    host.cmd('route add default gw %s dev %s-eth0' % (routerip, host.name))
    ips = IP_SETTING[host.name].split(".")
    host.cmd('route del -net %s.0.0.0/8 dev %s-eth0' % (ips[0], host.name))

def set_default_route_client(host):
    info('*** setting default gateway of client %s\n' % host.name)
    for eth in ['sw0-eth1', 'sw0-eth2']:
        swip = IP_SETTING[eth]
        pref = ".".join(swip.split(".")[:-1]) + ".0"
        print pref
        check_call('route add -net %s/24 gw 10.0.1.1 dev client-eth0' % (pref), shell = True)

def get_ip_setting():
    try:
        with open(IPCONFIG_FILE, 'r') as f:
            for line in f:
                if( len(line.split()) == 0):
                  break
                name, ip = line.split()
                print name, ip
                IP_SETTING[name] = ip
            info( '*** Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
    except EnvironmentError:
        exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)

def cs144net():
    stopserver()
    "Create a simple network for cs144"
    get_ip_setting()
    topo = CS144Topo()
    info( '*** Creating network\n' )
    net = Mininet( topo=topo, controller=RemoteController, ipBase=IPBASE )
    net.start()
    server1, client, router = net.get( 'server1', 'client', 'sw0')
    s1intf = server1.defaultIntf()
    s1intf.setIP('%s/8' % IP_SETTING['server1'])
    clintf = client.defaultIntf()
    clintf.setIP('%s/8' % IP_SETTING['client'])
    server1.setIP("184.72.104.217/24")


    for host in [server1]:
        set_default_route(host)
    set_default_route_client(client)
    startserver( server1, client )
    CLI( net )
    stopserver()
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    cs144net()
