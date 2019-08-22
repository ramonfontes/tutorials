#!/usr/bin/env python
import sys
import os
from binascii import hexlify

from scapy.all import sniff
from scapy.all import TCP, Raw


def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234 and Raw in pkt:
        pkt = pkt.lastlayer()
        pktHex = hexlify(str(pkt))
        bssid = pktHex[0:12]
        mac = pktHex[12:23]
        print "%s handovers to %s" % (mac, bssid)
        os.system("./run-code.sh")
    sys.stdout.flush()


def main():
    #ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
