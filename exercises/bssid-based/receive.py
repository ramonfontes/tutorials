#!/usr/bin/env python
import sys
import os
from binascii import hexlify

from scapy.all import sniff
from scapy.all import TCP, Raw

allowed_bssids = ['020000000200']
reg_mac = []

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234 and Raw in pkt:
        pkt = pkt.lastlayer()
        pktHex = hexlify(str(pkt))
        bssid = pktHex[0:12]
        mac = pktHex[12:24]

        if bssid in allowed_bssids and mac in reg_mac:
            if os.path.exists("%s.txt" % mac):
                print "Allowing packets from MAC %s" % (mac)
                os.system("./run-code-allow.sh")
                os.system("rm %s.txt" % mac)

        if bssid not in allowed_bssids:
            if os.path.exists("drop.txt"):
                reg_mac.append(mac)
                print "Dropping packets from BSSID %s" % (bssid)
                os.system("./run-code-drop.sh")
                os.system("rm drop.txt")
                os.system("touch %s.txt" % mac)
    sys.stdout.flush()


def main():
    #ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = 'eth0'
    os.system('rm *.txt')
    os.system('touch drop.txt')
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
