from scapy.all import *

class IntHeader(Packet):
    fields_desc = [ ByteField("old_proto", 0),
                    ByteField("int_total_num", 0)]

class IntData(Packet):
    fields_desc = [ ByteField("ingress_port", 0),
                    ByteField("egress_port", 0)] 
    

