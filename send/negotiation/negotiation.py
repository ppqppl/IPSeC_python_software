from scapy.all import *
import sys

from PowerOnScripts.sad_spd_python.ubuntu.sad_mgnt_service import whole_pkt

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')

from utils import *

class negotiation_pkt:
    dst_ip = "192.168.1.1"
    dst_port = "8080"
    dst_mask = "255.255.255.255"
    src_ip = "192.168.1.1"
    src_port = "8080"
    src_mask = "255.255.255.255"
    outer_dst_ip = "192.168.1.1"
    op = 1  # 1 request , 2 respond
    message_head = b''
    mgnt_dma_route_header = b''
    messgae_load = b''
    whole_pkt = b''

    def __init__(self,dst_ip,src_ip,outer_dst_ip,dst_port,src_port,op):
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.src_port = src_port
        self.outer_dst_ip = outer_dst_ip
        self.op = 1 if op == "request" else 2


    def config_whole_pkt(self):

        return self.whole_pkt

def set_sad_pkt(dst_ip,src_ip,outer_dst_ip,dst_port,src_port,op):
        negotiation_pkt_obj = negotiation_pkt(dst_ip,src_ip,outer_dst_ip,dst_port,src_port,op)
        send_sad(negotiation_pkt_obj)

def send_sad(negotiation_pkt_obj):
    whole_pkt = negotiation_pkt_obj.config_whole_pkt()
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')
