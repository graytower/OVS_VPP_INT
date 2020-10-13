import struct
import socket

class parse():
    def filter(self, pkt_raw):  # filter int packet
        pkt_len = len(pkt_raw)
        pkt = struct.unpack("!14s%ds" % (pkt_len - 14), pkt_raw)
        ethernet = self.parse_ethernet(pkt[0])
        if ethernet == 0x0800:
            pkt = struct.unpack("!20s%ds" % (pkt_len - 14 - 20), pkt[1])
            ipv4_info = self.parse_ipv4(pkt[0])

            if ipv4_info == 200:
                pkt = struct.unpack("!8s%ds" % (pkt_len - 14 - 20 - 8), pkt[1])
                udp_info = self.parse_udp(pkt[0])

                pkt = struct.unpack("!2s%ds" % (pkt_len - 14 - 20 - 8 - 2), pkt[1])
                int_md_num = self.parse_int_header(pkt[0])
                if int_md_num != 0:
                    data = self.int_pro(int_md_num, pkt[1])
                    return data
        
        else:
            return False

    def int_pro(self, n, pkt_raw):
        pkt_len = len(pkt_raw)
        int_list = []
        fmt = "!"
        for i in range(n):
            fmt = fmt + "2s"
        
        pkt = struct.unpack("%s%ds" % (fmt, pkt_len - n * 2), pkt_raw)
        
        for i in range(n):
            int_info = self.parse_int(pkt[i])
            int_list.append(int_info)
            
        return int_list
                
    def parse_int(self, pkt):
        inthdr = struct.unpack("!BB", pkt)
        # sw_id = inthdr[0]
        ingress_port = inthdr[0]
        egress_port = inthdr[1]
        # egress_global_tstamp = (inthdr[4] << 16) + inthdr[5]
        # enq_qdepth = (inthdr[10] << 8) + inthdr[11]
        # deq_qdepth = (inthdr[-2] << 8) + inthdr[-1]
        # time_delta = inthdr[-4]
        
        # print 'ingress_port: ', ingress_port
        print 'hop_lantency ', egress_port 
        return ingress_port, egress_port

    def parse_ethernet(self, pkt):
        ethernet = struct.unpack("!6B6BH", pkt)
        ethernet_str = []
        for i in range(12):
            temp = ethernet[i]
            temp = (hex(temp))[2:]
            if len(temp) == 1:
                temp = "0" + temp
            ethernet_str.append(temp)

        dstAddr = "%s:%s:%s:%s:%s:%s" % (
            ethernet_str[0], ethernet_str[1], ethernet_str[2], ethernet_str[3], ethernet_str[4], ethernet_str[5])
        srcAddr = "%s:%s:%s:%s:%s:%s" % (
            ethernet_str[6], ethernet_str[7], ethernet_str[8], ethernet_str[9], ethernet_str[10], ethernet_str[11])
        etherType = ethernet[12]

        # print 'src: ', srcAddr
        # print 'dst: ', dstAddr
        # print 'etherType: ', etherType

        return etherType

    def parse_ipv4(self, pkt):
        ipv4 = struct.unpack("!BBHHHBBH4s4s", pkt)
        version = (ipv4[0] & 0xf0) >> 4  # 1
        ihl = ipv4[0] & 0x0f  # 2
        diffserv = ipv4[1]  # 3
        totalLen = ipv4[2]  # 4
        identification = ipv4[3]  # 5
        flags = (ipv4[4] & 0xe000) >> 13  # 6
        fragOffset = ipv4[4] & 0x1fff  # 7
        ttl = ipv4[5]  # 8
        protocol = ipv4[6]  # 9
        hdrChecksum = ipv4[7]  # 10
        srcAddr = ipv4[8]  # 11
        dstAddr = ipv4[9]  # 12
        srcAddr = socket.inet_ntoa(srcAddr)
        dstAddr = socket.inet_ntoa(dstAddr)

        # if protocol == 200:        
        #    print 'src: ', srcAddr
        #    print 'dst: ', dstAddr
        #    print 'totalLen: ', totalLen
        #    print 'protocol: ', protocol

        return protocol

    
    def parse_udp(self, pkt):
        udp = struct.unpack("!HHH2s", pkt)
        srcPort = udp[0]
        dstPort = udp[1]
        udplen = udp[2]

        # print 'srcPort: ', srcPort
        # print 'dstPort: ', dstPort
        # print 'udplen: ', udplen
        return srcPort, dstPort, udplen

    def parse_int_header(self, pkt):
        int_header = struct.unpack("!BB", pkt)
        old_proto = int_header[0]
        total_num = int_header[1]

        # print 'old_proto: ', old_proto
        # print 'total_num: ', total_num
        return total_num


if __name__ == "__main__":
    pass

