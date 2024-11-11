from scapy.all import *
import sys

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')

from utils import *
from send_pkt import *

cur_seq = 0

total_pkt_cnt = 0
sad_index_num = 1

sad_pkt_list = []

class sad_pkt:
    cue_seq = 0
    op_code = "ADD"
    dst_mac = "08:11:22:33:44:ab"
    src_mac = "08:11:22:33:44:ab"
    dst_chip_id = "00"
    dst_mode_id = "00"
    src_chip_id = "03"
    src_mode_id = "11"
    sa_valid = 1
    sa_index = 1001
    tunnel_dip = "100.100.4.1"
    tunnel_sip = "100.100.3.1"
    key_index = "87654321"
    sa_status = 0 # 0-Unnegotiate; 1-Negotiating; 2-In Service;
    sa_anti_replay = 0 # 0-Disable anti-replay; 1-Enable anti-replay;
    sa_type = 0 # 0-Unicast; 1-Multicast; 2-Management; 3-Neotiation;
    sa_op_code = 3 # 1-Direct; 2-Drop; 3-Encryption
    sa_packet_mtu = 1536
    channel_id = 0 # 0-Normal; 1-CPU; 2-Loop;
    transmit_mode = 1 # 1-Tunnel; 2-Transmission;
    exchange_port = 0 # 0-Disable; 1-Enable;
    post_to_cpu = 0 # 0-Disable; 1-Enable;
    multicast_index = 0
    alg_type = 0
    firewall_dip = "192.168.1.1"
    firewall_sip = "192.168.1.1"
    firewall_dmask = "255.255.255.255"
    firewall_smask = "255.255.255.255"
    firewall_dport = 456
    firewall_sport = 123
    protocol = "UDP"
    message_head = b''
    mgnt_dma_route_header = b''
    messgae_load = b''
    whole_pkt = b''
    # def __init__(self,op_code,sa_index,key_index,src_mode,dst_mode,tunnel_dip,tunnel_sip,protocol):
    #     self.sa_index = sa_index
    #     self.key_index = key_index
    #     self.dst_chip_id = dst_mode[0:2:1]
    #     self.dst_mode_id = dst_mode[2:4:1]
    #     self.src_chip_id = src_mode[0:2:1]
    #     self.src_mode_id = src_mode[2:4:1]
    #     self.op_code = op_code
    #     self.tunnel_dip = tunnel_dip
    #     self.tunnel_sip = tunnel_sip
    #     self.protocol = protocol
    def __init__(self,tunnel_dip, tunnel_sip, sa_index, key_index, protocol,dst_chip):
        global sad_index_num
        sad_index_num += 1
        self.tunnel_dip = tunnel_dip
        self.tunnel_sip = tunnel_sip
        self.sa_index = sa_index
        self.key_index = key_index
        self.protocol = protocol
        if dst_chip == "inner":
            self.dst_chip_id = "06"
            self.dst_mode_id = "02"
        elif dst_chip == "outter":
            self.dst_chip_id = "04"
            self.dst_mode_id = "02"

    def set_sa_type(self,sa_type):
        self.sa_type = sa_type
    def set_sa_op_code(self,sa_op_code):
        self.sa_op_code = sa_op_code
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
        self.messgae_load += (str_2_hexbytes("0100") + str_2_hexbytes(op_code_to_str(self.op_code)) + str_2_hexbytes(str(self.sa_valid)) + get_sa_index(self.sa_index) +
                              str_2_hexbytes(ipstr_2_hexstr(self.tunnel_dip)) + str_2_hexbytes(ipstr_2_hexstr(self.tunnel_sip)) + str_2_hexbytes(ipstr_2_hexstr(self.firewall_dip)) +
                              str_2_hexbytes(ipstr_2_hexstr(self.firewall_sip)) + str_2_hexbytes(ipstr_2_hexstr(self.firewall_dmask)) + str_2_hexbytes(ipstr_2_hexstr(self.firewall_smask)) +
                              get_port(self.firewall_dport) + get_port(self.firewall_sport) + str_2_hexbytes(protocol_to_str(self.protocol)) + blank.to_bytes(11,byteorder='big'))
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

def get_sa_index(data):
    data_hex = hex(data)
    data_str = str(data_hex)[2:]
    data_str_reserve = data_str[::-1]
    data_out_reserve = data_str_reserve.ljust(8,'0')
    return str_2_hexbytes(data_out_reserve[::-1])

def get_port(data):
    data_hex = hex(data)
    data_str = str(data_hex)[2:]
    data_str_reserve = data_str[::-1]
    data_out_reserve = data_str_reserve.ljust(4,'0')
    return str_2_hexbytes(data_out_reserve[::-1])

def op_code_to_str(op_code):
    if op_code == 'ADD':
        return "01"
    elif op_code == 'DEL':
        return "02"
    elif op_code == 'CLR':
        return "03"
    else:
        return "00"

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

def set_sad_pkt(tunnel_dip,tunnel_sip,sa_index,key_index,protocol,dst_chip):
    length = len(protocol)
    for i in range(length):
        proto = protocol[i]
        sad_pkt_obj = sad_pkt(tunnel_dip, tunnel_sip, sa_index, key_index, proto,dst_chip)
        send_sad(sad_pkt_obj)

def send_sad_sa_0(sad_pkt_obj):
    sad_pkt_obj.set_sa_type(0)
    sad_pkt_obj.set_sa_op_code(2)
    whole_pkt = sad_pkt_obj.config_whole_pkt()
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')


def send_sad(sad_pkt_obj):
    whole_pkt = sad_pkt_obj.whole_pkt
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')



