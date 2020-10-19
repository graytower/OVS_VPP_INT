#!/usr/bin/env python
import sys
import time
from int_hdrs import *
from scapy.all import *

def main():

    pkt = Ether()/IP(dst='172.16.2.2',proto=222)/UDP()/'xyz123abc'

    try:
        bt = time.time()
        sendp(pkt)
        et = time.time()
        print 't: ', et - bt
    except KeyboardInterrupt:
        sys.exit()

if __name__ == '__main__':
    main()
