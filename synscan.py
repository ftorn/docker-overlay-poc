#!/usr/bin/env python
"""SynScan Docker Overlay Network \
   by Francesco Tornieri \
   ft '\At\' verona-wireless.net"""

#To send a syn scan is mandatory to know:
#1-srcmac/dstmac, not randomic -see below-
#2-srcip/dstip, not randomic -the sysops use often the same network classes-
#3-vni, not randomic
#
#The 'srcmac/dstmac' vars define the macaddress of the container in the overlay network and aren't randomic
# 
#
#The 'srcip/dstip' vars define the ip address of the containers in the overlay network 
#
#The 'dport' var defines the range of containers tcp ports
#
#The 'hostdocker' var defines the ip address of the hosts docker
#
#The 'myip' var define your host ip address

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading, sys, argparse

load_contrib('vxlan')

#CHANGE THIS#
myip = '192.168.1.76'
srcmac = ['02:42:0a:0a:0a:01','02:42:0a:0a:0a:0a']
dstmac = ['02:42:0a:0a:0a:03','02:42:0a:0a:0a:02']
srcip = ['10.10.10.2','10.10.10.3']                                                  
dstip = ['10.10.10.2','10.10.10.3']
dport = [80,443]
hostdocker = ['192.168.1.70','192.168.1.71']
vnindex = [256]

#DON'T CHANGE#
conf.checkIPaddr = False
conf.sniff_promisc = True
conf.verb = 0
sport = random.randint(1024,65535)

def synscan():
	ether=Ether()
	ip1=IP(src=myip,dst=hostdocker)
	udp=UDP(sport=sport,dport=4789,chksum=0)/VXLAN(vni=vnindex)
	ether1=Ether(src=srcmac,dst=dstmac)
	ip2=IP(src=srcip,dst=dstip,flags="DF")
	syn=TCP(sport=sport,dport=dport)
	
	scan = ether/ip1/udp/ether1/ip2/syn
	srp(scan, timeout = 3)

def pkt_callback(pkt):
    f = lambda x: x == 18 and "IP: " + str(pkt[IP].src) + " ==> Open port: " + str(pkt[TCP].sport) or None
    return f(pkt[TCP].flags)

def main():
    t = threading.Thread(target=synscan)
    t.start()
    print "Send fake vxlan packet...please wait..."
    print "ctrl+c to terminate\n"
    raw = sniff(count=100, filter="udp port 4789", prn=pkt_callback, store=0)

if __name__ == '__main__':
    main()
