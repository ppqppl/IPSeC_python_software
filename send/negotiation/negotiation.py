from scapy.all import *
import sys

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')

from utils import *

class negotiation_pkt:
    dst_ip = "192.168.1.1"
    dst_port = "8080"
    message_head = b''
    mgnt_dma_route_header = b''
    messgae_load = b''
    whole_pkt = b''

def send_sad(negotiation_pkt_obj):
    whole_pkt = negotiation_pkt_obj.whole_pkt
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')
