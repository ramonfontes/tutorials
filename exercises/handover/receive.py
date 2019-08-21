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
        if pktHex == '020000000200':
            if os.path.exists('run-code.sh'):
                print "handover to 02:00:00:00:02:00"
                os.system("./run-code.sh")
                os.system("rm run-code.sh")
    sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[3]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
