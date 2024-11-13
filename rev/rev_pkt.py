from scapy.all import *
import sys

from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether

sys.path.append("../")
sys.path.append("../sql_console")
# import utils
from sqlite3_utils import *



def callback_sniff_1000(pkt_data):
    # pkt_data.show()
    if pkt_data.haslayer(IP):
        pkt_data_ip = pkt_data[IP]
        if hasattr(pkt_data_ip,'proto'):
            print(pkt_data[IP].proto)
        else:
            print("no proto")
    # dst_mac = pkt_data['Ethernet'].dst
    # src_mac = pkt_data['Ethernet'].src
    # data = pkt_data['Raw'].load
    # dst_chip_id = data[2]
    # dst_mode_id = data[3]
    # src_chip_id = data[4]
    # src_mode_id = data[5]
    # seq = data[0] + data[1]
    # pkt_obj = pkt_class(dst_mac,src_mac,pkt_data)
    # pkt_obj.set_dst_chip_id(dst_chip_id)
    # pkt_obj.set_dst_mode_id(dst_mode_id)
    # pkt_obj.set_src_chip_id(src_chip_id)
    # pkt_obj.set_src_mode_id(src_mode_id)
    # pkt_obj.set_seq(seq)

def rev_socket_1000(threadname):
    print("Thread " + threadname + " start!!")
    print(11)
    # packet = sniff(iface='WLAN',filter="ether proto 0x1000",count=1,prn=callback_sniff_1000)
    packet = sniff(iface='WLAN',prn = callback_sniff_1000)
    # print(packet)

def pkt_judge(pkt_data):
    global dst_mode_id
    global dst_chip_id
    global src_mode_id
    global src_chip_id
    global tag
    print(pkt_data['Raw'].load)
    dst_mode_id = pkt_data['Raw'].load[16]
    dst_chip_id = pkt_data['Raw'].load[17]
    src_mode_id = pkt_data['Raw'].load[18]
    src_chip_id = pkt_data['Raw'].load[19]
    if dst_chip_id == b'\x01':
        print("FMU")
        if dst_chip_id == b'\x01':
            print("negotiation")
        elif dst_chip_id == b'\x01':
            print("negotiation")
    elif dst_chip_id == b'\x02':
        print("IMU")
    elif dst_chip_id == b'\x03':
        print("MMU")

rev_socket_1000('a')
# print_str("hello")