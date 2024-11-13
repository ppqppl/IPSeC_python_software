from scapy.all import *
import sys

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')

from utils import *
# from send_pkt import *

class audit_pkt:
    cue_seq = 0
    op_code = "RED"
    dst_mac = "00:E0:4C:82:29:F5"
    src_mac = "6C:02:E0:94:67:DC"
    dst_chip_id = "00"
    dst_mode_id = "00"
    src_chip_id = "03"
    src_mode_id = "11"
    message_head = b''
    mgnt_dma_route_header = b''
    messgae_load = b''
    whole_pkt = b''

    def __init__(self,dst_chip,op_code):
        self.op_code = op_code
        if dst_chip == "inner":
            self.dst_chip_id = "06"
            self.dst_mode_id = "50"
        elif dst_chip == "outter":
            self.dst_chip_id = "04"
            self.dst_mode_id = "50"
        elif dst_chip == "isolation":
            self.dst_chip_id = "04"
            self.dst_mode_id = "50"

    # def set_op_code(self, op_code):
    #     self.op_code = op_code

    def config_message_head(self):
        self.message_head = (str_2_hexbytes(macstr_2_str(self.dst_mac)) + get_mac_address() + str_2_hexbytes("1000") + self.cue_seq.to_bytes(2,byteorder='big'))
        return self.message_head

    def config_mgnt_dma_route_header(self):
        blank = 0
        self.mgnt_dma_route_header = (str_2_hexbytes(self.dst_chip_id) + str_2_hexbytes(self.dst_mode_id) + str_2_hexbytes(self.src_chip_id) +
                                       str_2_hexbytes(self.src_mode_id) + blank.to_bytes(12,byteorder='big'))
        return self.mgnt_dma_route_header

    def config_messgae_load(self):
        blank = 0
        self.messgae_load = (op_code_to_str(self.op_code) + blank.to_bytes(15,byteorder='big'))
        return self.messgae_load

    def config_whole_pkt(self):
        self.whole_pkt = self.config_message_head() + self.config_mgnt_dma_route_header() + self.config_messgae_load()
        return self.whole_pkt

def get_mac_address():
    mac = uuid.UUID(int = uuid.getnode())
    mac_str = str(mac).split('-')[-1]
    res = bytes()
    for i in range(0,6):
        res += (int(mac_str[i*2:i*2+2],16)).to_bytes(1,byteorder='big')
    return res

def op_code_to_str(op_code):
    if op_code == 'RED':
        return b'\x01'
    elif op_code == 'RST':
        return b'\x02'

def set_audit_pkt(dst_chip,op_code):
        audit_pkt_obj = audit_pkt(dst_chip, op_code)
        send_audit(audit_pkt_obj)

def send_audit(audit_pkt_obj):
    whole_pkt = audit_pkt_obj.config_whole_pkt()
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')

# op_code_to_str('RST')
# print(op_code_to_str('RST'))
# pkt_obj = audit_pkt('inner')
# print(pkt_obj.config_message_head())
# print(pkt_obj.config_mgnt_dma_route_header())
# print(pkt_obj.config_messgae_load())
set_audit_pkt('outter','RST')

