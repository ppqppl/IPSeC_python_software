from scapy.all import *
import sys

from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether

sys.path.append("../")
sys.path.append("../sql_console")
import utils
from sqlite3_utils import *

def callback_sniff_1000(pkt_data):
    # pkt_data.show()
    dst_mac = pkt_data['Ethernet'].dst
    src_mac = pkt_data['Ethernet'].src
    data = pkt_data['Raw'].load
    dst_chip_id = data[2]
    dst_mode_id = data[3]
    src_chip_id = data[4]
    src_mode_id = data[5]
    op_mode = data[6]
    seq = data[0] + data[1]
    pkt_data = data[18:]
    hex_dump(pkt_data)
    whole_pkt = ""
    whole_pkt[20] = '01' if op_mode == "01" else 0

    send_pkt(whole_pkt)

def rev_pkt_1000(threadname):
    print("Thread " + threadname + " start!!")
    print(11)
    packet = sniff(iface='WLAN',filter="ether proto 0x1000",prn=callback_sniff_1000)
    # packet = sniff(iface='WLAN',prn = callback_sniff_1000)
    # packet = sniff(filter = "arp")
    # print(packet)

# def rev_pkt_arp(threadname):


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

def send_pkt(whole_pkt):
    hex_dump(whole_pkt)
    send(whole_pkt,iface='WLAN')

# rev_pkt_1000('a')
