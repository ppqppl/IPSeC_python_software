from scapy.all import *
import sys

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')
# sys.path.append('../send_pkt')
from utils import *
# from send_pkt import *

cur_seq = 0

# total_pkt_cnt = 0
# spd_index_num = 1
# spd_pkt_list = []

class anti_reply_pkt:
    cue_seq = 0

    src_ip = "192.168.1.1"
    dst_ip = "192.168.1.2"
    dst_mac = "00:87:24:06:18:21"
    src_mac = "50:08:72:44:18:34"
    dst_chip_id = "05"
    dst_mode_id = "01"
    src_chip_id = "03"
    src_mode_id = "11"
    op_code = "CLR1"
    sa_index = 2000

    message_head = b''
    anti_reply_header = b''
    messgae_load = b''
    whole_pkt = b''

    def __init__(self,dst_ip,src_ip,dst_mac,src_mac,dst_chip,op_code,sa_index):
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.op_code = op_code
        self.sa_index = sa_index
        if dst_chip == "dir_en":
            self.dst_chip_id = "05"
            self.dst_mode_id = "01"
        elif dst_chip == "dir_de":
            self.dst_chip_id = "05"
            self.dst_mode_id = "02"
    def set_op_code(self, op_code):
        self.op_code = op_code
    def set_sa_index(self, sa_index):
            self.sa_index = sa_index
    def config_message_head(self):
        self.message_head = (str_2_hexbytes(macstr_2_str(self.dst_mac)) + get_mac_address() + str_2_hexbytes("1000") + self.cue_seq.to_bytes(2,byteorder='big'))
        return self.message_head
    def config_anti_reply_header(self):
        blank = 0
        self.anti_reply_header = (str_2_hexbytes(self.dst_chip_id) + str_2_hexbytes(self.dst_mode_id) + str_2_hexbytes(self.src_chip_id) +
                                       str_2_hexbytes(self.src_mode_id) + blank.to_bytes(12,byteorder='big'))
        return self.anti_reply_header
    def config_messgae_load(self):
        blank = 0
        self.messgae_load = (str_2_hexbytes("0100") + op_code_to_str(self.op_code)+blank.to_bytes(1,byteorder='big') +get_sa_index(self.sa_index) + blank.to_bytes(8,byteorder='big'))
        return self.messgae_load

    def config_whole_pkt(self):
        self.whole_pkt = self.config_message_head() + self.config_anti_reply_header() + self.config_messgae_load()
        return self.whole_pkt

def get_mac_address():
    mac = uuid.UUID(int = uuid.getnode())
    mac_str = str(mac).split('-')[-1]
    res = bytes()
    for i in range(0,6):
        res += (int(mac_str[i*2:i*2+2],16)).to_bytes(1,byteorder='big')
    return res

def op_code_to_str(op_code):
    if op_code == 'CLR0':
        return b'\x00'
    elif op_code == 'CLR1':
        return b'\x01'
    else:
        return b'\x00'

def get_sa_index(data):
    data_hex = hex(data)
    data_str = str(data_hex)[2:]
    data_str_reserve = data_str[::-1]
    data_out_reserve = data_str_reserve.ljust(8,'0')
    return str_2_hexbytes(data_out_reserve[::-1])

def set_anti_reply_pkt(dst_ip,src_ip,dst_mac,src_mac,dst_chip,op_code,sa_index):
    anti_reply_obj = anti_reply_pkt(dst_ip,src_ip,dst_mac,src_mac,dst_chip,op_code,sa_index)
    send_anti_reply(anti_reply_obj)

def send_anti_reply(anti_reply_obj):
    whole_pkt = anti_reply_obj.config_whole_pkt()
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')


# set_anti_reply_pkt("192.168.133.128","192.168.99.2","6C:02:E0:94:67:DC","00:E0:4C:82:29:F5","dir_en","CLR1",2011)

