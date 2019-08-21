#!/usr/bin/env python

import subprocess
import random
import sys
import os

from scapy.all import get_if_hwaddr, sniff
from scapy.all import Dot11
from scapy.all import Ether, IP, TCP

from scapy.all import sendp
from scapy.all import Packet
from scapy.all import LongField, StrField, MACField
from scapy.all import bind_layers


class P4wifi(Packet):
    name = "P4wifi"
    fields_desc = [ MACField("bssid", None)]

bind_layers(Ether, P4wifi, type=0x1234)
mn_dir = "~/mininet-wifi"

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

def get_if(node):
    iface = '%s-wlan0' % node
    return iface

def pkt_callback(pkt):

    if pkt.haslayer(Dot11):

        addr = "10.0.3.3"
        iface = get_if(sys.argv[1])

        cmd = ["%s/util/m %s iw dev "
               "%s-wlan0 link | grep Connected | "
               "awk 'NR==1{print $3}'" % (mn_dir, sys.argv[1], sys.argv[1])]
        address = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, err) = address.communicate()
        bssid = str(out).split('\n')[0]

        if bssid:
            #if bssid == '02:00:00:00:02:00':
            pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt / IP(dst=addr) / \
                  TCP(dport=1234, sport=random.randint(49152, 65535)) \
                  / P4wifi(bssid=bssid)
            pkt.show()
            sendp(pkt, iface=iface, verbose=False)

if len(sys.argv)<2:
    print 'pass 1 arguments: <node>'
    exit(1)

os.system('cp run-code.sh.bkp run-code.sh')
os.system("%s/util/m %s iw dev %s-wlan0 interface add mon%s "
          "type monitor" % (mn_dir, sys.argv[1], sys.argv[1], sys.argv[1][3:]))
os.system("%s/util/m %s ifconfig mon%s up" % (mn_dir, sys.argv[1], sys.argv[1][3:]))
sniff(iface="mon%s" % sys.argv[1][3:], prn=pkt_callback, store=0)
