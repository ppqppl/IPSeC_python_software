from scapy.all import *
import sys
sys.path.append("..")
sys.path.append("../utils")
sys.path.append("./sad_spd")
from utils import *
from pkt_class import *
import sad
import spd

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

def send_sad_pkt(tunnel_dip,tunnel_sip,sa_index,key_index,protocol,dst_chip):
    sad.set_sad_pkt(tunnel_dip,tunnel_sip,sa_index,key_index,protocol,dst_chip)

def send_spd_pkt(src_ip,dst_ip,src_port,dst_port,protocol,dst_chip):
    spd.set_spd_pkt(src_ip,dst_ip,src_port,dst_port,protocol,dst_chip)