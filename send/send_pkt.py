from scapy.all import *
import sys
sys.path.append("..")
sys.path.append("../utils")
from utils import *
from pkt_class import *

cur_seq = 0

def send_negotiation_phase_1(pkt_obj):
    print("Send negotiation phase 1")
    dst_mac = str_2_hexbytes(pkt_obj.dst_mac)
    whole_pkt = dst_mac
    pkt_obj.set_whole_pkt(whole_pkt)
    send_pkt(pkt_obj.whole_pkt)

def send_negotiation_phase_2(pkt_obj):
    print("Send negotiation phase 2")
    send_pkt(pkt_obj.whole_pkt)

def send_negotiation_phase_3(pkt_obj):
    print("Send negotiation phase 3")
    send_pkt(pkt_obj.whole_pkt)

def send_pkt(whole_pkt) :
    # print(whole_pkt)
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')

