#!/usr/bin/env python

import random

from scapy.all import sendp, get_if_list, get_if_hwaddr, sniff
from scapy.all import Dot11
from scapy.all import Ether, IP, UDP, TCP

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import StrFixedLenField, XByteField, IntField, LongField
from scapy.all import bind_layers


class P4wifi(Packet):
    name = "P4wifi"
    fields_desc = [ LongField("rssi", 0)]

bind_layers(Ether, P4wifi, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

def get_if():
    iface = 'sta1-wlan0'
    return iface

def pkt_callback(pkt):

    if pkt.haslayer(Dot11):

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

        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / \
              TCP(dport=1234, sport=random.randint(49152, 65535)) \
              / P4wifi(rssi=abs(rssi))

        pkt = pkt / ' '

        pkt.show()
        sendp(pkt, iface=iface, verbose=False)


sniff(iface="mon0", prn=pkt_callback, store=0)
