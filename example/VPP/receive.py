#!/usr/bin/env python

import socket
import parse
import os

from scapy.all import get_if_addr

class receive():
    def sniff(self):
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        src_ip = get_if_addr("eth0")
        n = 0
        parse1 = parse.parse()
        while True:
            data = s.recv(2048)
            n = n + 1
            if not data:
                print ("Client has exist")
                continue         
            
            rs = parse1.filter(data)
            # print 'n: ', n

        s.close()


if __name__ == "__main__":
    receive1 = receive()
    receive1.sniff()

