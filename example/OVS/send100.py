#!/usr/bin/env python
import sys
import time
from int_hdrs import *
from scapy.all import *

def main():

    pkt = Ether()/IP(dst='10.0.0.2')/UDP()/'xyz123abc'

    pkt2 = Ether()/IP(dst='10.0.0.2',proto=200)/UDP()/IntHeader(old_proto=17,int_total_num=1)/IntData(ingress_port=9,egress_port=8)/'123abc456'
                
    try:
        bt = time.time()
        sendp(pkt, count=100, inter=0.009)
        et = time.time()
        print 't: ', et - bt
    except KeyboardInterrupt:
        sys.exit()

if __name__ == '__main__':
    main()
