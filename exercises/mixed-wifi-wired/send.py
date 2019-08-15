#!/usr/bin/env python

import random

from scapy.all import sendp, get_if_list, get_if_hwaddr, sniff
from scapy.all import Dot11
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "wlan0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find wlan0 interface"
        exit(1)
    iface = 'sta1-wlan0'
    return iface

def pkt_callback(pkt):

    if pkt.haslayer(Dot11):

        ssid = None
        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info
        #if len(sys.argv)<3:
        #    print 'pass 2 arguments: <destination> "<message>"'
        #    exit(1)
        try:
            extra = pkt.notdecoded
            rssi = -(256 - ord(extra[-4:-3]))
        except:
            rssi = 0

        #addr = socket.gethostbyname(sys.argv[1])
        addr = "10.0.3.3"
        iface = get_if()
        print "sending on interface %s to %s" % (iface, str(addr))
        pktt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pktt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / pkt
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

sniff(iface="mon0", prn=pkt_callback, store=0)