#!/usr/bin/env python

import random
import sys
import os

from scapy.all import get_if_hwaddr, sniff
from scapy.all import Dot11
from scapy.all import Ether, IP, TCP

from scapy.all import sendp
from scapy.all import Packet
from scapy.all import LongField
from scapy.all import bind_layers


class P4wifi(Packet):
    name = "P4wifi"
    fields_desc = [ LongField("rssi", 0)]

bind_layers(Ether, P4wifi, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

def get_if(node):
    iface = '%s-wlan0' % node
    return iface

def pkt_callback(pkt):

    if pkt.haslayer(Dot11):

        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info
        try:
            extra = pkt.notdecoded
            rssi = -(256 - ord(extra[-4:-3]))
        except:
            rssi = 0

        addr = "10.0.3.3"
        iface = get_if(sys.argv[1])

        if int(rssi) > - 70:
            pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt / IP(dst=addr) / \
                  TCP(dport=1234, sport=random.randint(49152, 65535)) \
                  / P4wifi(rssi=abs(rssi))

            pkt.show()
            sendp(pkt, iface=iface, verbose=False)

if len(sys.argv)<2:
    print 'pass 1 arguments: <node>'
    exit(1)

mn_dir = "~/mininet-wifi"
os.system("%s/util/m %s iw dev %s-wlan0 interface add mon%s "
          "type monitor" % (mn_dir, sys.argv[1], sys.argv[1], sys.argv[1][3:]))
os.system("%s/util/m %s ifconfig mon%s up" % (mn_dir, sys.argv[1], sys.argv[1][3:]))
sniff(iface="mon%s" % sys.argv[1][3:], prn=pkt_callback, store=0)
