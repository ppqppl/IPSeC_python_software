from scapy.all import *
import sys

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')

from utils import *
from send_pkt import *

cur_seq = 0

total_pkt_cnt = 0
spd_index_num = 1

spd_pkt_list = []

class spd_pkt:
    cue_seq = 0
    op_code = "ADD"
    ip_ver = 4
    dst_mac = "08:11:22:33:44:ab"
    src_mac = "08:11:22:33:44:ab"
    dst_chip_id = "00"
    dst_mode_id = "00"
    src_chip_id = "03"
    src_mode_id = "11"
    protocol = "UDP"
    src_port = "0"
    dst_port = "0"
    sa_index = 0
    src_ip = "192.168.1.1"
    src_mask = "255.255.255.255"
    dst_ip = "192.168.1.2"
    dst_mask = "255.255.255.255"
    message_head = b''
    mgnt_dma_route_header = b''
    messgae_load = b''
    whole_pkt = b''

    def __init__(self,src_ip,dst_ip,src_port,dst_port,protocol,dst_chip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        if dst_chip == "inner":
            self.dst_chip_id = "06"
            self.dst_mode_id = "01"
        elif dst_chip == "outter":
            self.dst_chip_id = "04"
            self.dst_mode_id = "01"
    def set_op_code(self, op_code):
        self.op_code = op_code
    def config_message_head(self):
        self.message_head += (str_2_hexbytes(macstr_2_str(self.dst_mac)) + get_mac_address() + str_2_hexbytes("1000") + self.cue_seq.to_bytes(2,byteorder='big'))
        return self.message_head
    def config_mgnt_dma_route_header(self):
        blank = 0
        self.mgnt_dma_route_header += (str_2_hexbytes(self.dst_chip_id) + str_2_hexbytes(self.dst_mode_id) + str_2_hexbytes(self.src_chip_id) +
                                       str_2_hexbytes(self.src_mode_id) + blank.to_bytes(12,byteorder='big'))
        return self.mgnt_dma_route_header
    def config_messgae_load(self):
        blank = 0
        self.messgae_load += (str_2_hexbytes("0100") + str_2_hexbytes(op_code_to_str(self.op_code)) + str_2_hexbytes("04") + str_2_hexbytes(protocol_to_str(self.protocol)) +
                              blank.to_bytes(1,byteorder='big') + str_2_hexbytes(self.dst_port) + str_2_hexbytes(self.src_port) + blank.to_bytes(2,byteorder='big') +
                              get_sa_index(self.sa_index) + blank.to_bytes(12,byteorder='big') + str_2_hexbytes(ipstr_2_hexstr(self.src_ip)) + blank.to_bytes(12,byteorder='big') +
                              str_2_hexbytes(ipstr_2_hexstr(self.src_mask)) + blank.to_bytes(12,byteorder='big') + str_2_hexbytes(ipstr_2_hexstr(self.dst_ip)) +
                              blank.to_bytes(12,byteorder='big') + str_2_hexbytes(ipstr_2_hexstr(self.dst_mask)))

def get_mac_address():
    mac = uuid.UUID(int = uuid.getnode())
    mac_str = str(mac).split('-')[-1]
    res = bytes()
    for i in range(0,6):
        res += (int(mac_str[i*2:i*2+2],16)).to_bytes(1,byteorder='big')
    return res

def op_code_to_str(op_code):
    if op_code == 'ADD':
        return b'\x01'
    elif op_code == 'DEL':
        return b'\x02'
    elif op_code == 'CLR':
        return b'\x03'
    else:
        return b'\x00'

def protocol_to_str(protocol):
    if protocol == 'ICMP':
        return "01"
    elif protocol == 'UDP':
        return "11"
    elif protocol == 'TCP':
        return "06"
    elif protocol == 'ESP':
        return "32"
    else:
        return "00"

def get_sa_index(data):
    data_hex = hex(data)
    data_str = str(data_hex)[2:]
    data_str_reserve = data_str[::-1]
    data_out_reserve = data_str_reserve.ljust(8,'0')
    return str_2_hexbytes(data_out_reserve[::-1])

def set_spd_pkt(src_ip,dst_ip,src_port,dst_port,protocol,dst_chip):
    length = len(protocol)
    for i in range(length):
        proto = protocol[i]
        spd_pkt_obj = spd_pkt(src_ip,dst_ip,src_port,dst_port,protocol,dst_chip)
        send_spd(spd_pkt_obj)

def send_spd(spd_pkt_obj):
    whole_pkt = sad_pkt_obj.whole_pkt
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')
