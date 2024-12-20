from scapy.all import *
import sys

from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether

sys.path.append("../")
sys.path.append("../sql_console")
import utils
from sqlite3_utils import *

chip_mode_ip = {
    "sad" : {
        "chip" : "01",
        "mode" : "01",
    },
}

def callback_sniff_1000(pkt_data):
    blank = 0
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
    whole_pkt += src_mac
    whole_pkt += dst_mac
    whole_pkt += "0100"
    whole_pkt +=  seq
    whole_pkt += src_chip_id
    whole_pkt += src_mode_id
    whole_pkt += dst_chip_id
    whole_pkt += dst_mode_id
    whole_pkt += "01" if op_mode == "00" else "01"
    # whole_pkt[41] = '1' if op_mode == "01" else '0'
    whole_pkt += blank.to_bytes(11,byteorder='big')
    whole_pkt += pkt_data
    send_pkt(whole_pkt)

def rev_pkt_1000(threadname):
    print("Thread " + threadname + " start!!")
    packet = sniff(iface='WLAN',filter="ether proto 0x1000",prn=callback_sniff_1000)
    # packet = sniff(iface='WLAN',prn = callback_sniff_1000)
    # packet = sniff(filter = "arp")
    # print(packet)

def callback_sniff_arp(pkt_data):
    blank = 0
    cue_seq = 0
    dst_chip_ip = "01"
    dst_mode_ip = "01"
    src_chip_ip = "01"
    src_mode_ip = "01"
    dst_mac = pkt_data['Ethernet'].dst
    src_mac = pkt_data['Ethernet'].src
    src_ip = pkt_data['IP'].psrc
    dst_ip = pkt_data['IP'].pdst
    pkt_data.show()
    print(dst_mac)
    print(src_mac)
    ptype = pkt_data['ARP'].ptype
    op = pkt_data['ARP'].op
    op_mode = "01" if op == "00" else "00"

    whole_pkt_head = ""
    whole_pkt_head += dst_mac
    whole_pkt_head += src_mac

    whole_pkt = ""
    whole_pkt += dst_mac
    whole_pkt += src_mac
    whole_pkt += "1000"
    whole_pkt += cue_seq.to_bytes(2,byteorder='big')
    whole_pkt += dst_chip_ip
    whole_pkt += dst_mode_ip
    whole_pkt += src_chip_ip
    whole_pkt += src_mode_ip
    whole_pkt += op_mode
    whole_pkt += blank.to_bytes(11,byteorder='big')

    send_pkt(whole_pkt)

def rev_pkt_arp(threadname):
    print("Thread " + threadname + " start!!")
    packet = sniff(iface='WLAN',filter="arp",count = 1,prn=callback_sniff_arp)

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
rev_pkt_arp('a')
