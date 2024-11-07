import sys
sys.path.append("..")
from utils import *

cur_seq = 0

mac_dst_mac = "ffffffffffff"
mac_src_mac = "112233445566"

pkt_mac_head = mac_dst_mac + mac_src_mac

mac_head = {
    "negotiation" : {
        "mac_dst_mac" : "ffffffffffff",
        "mac_src_mac" : "010203040506",
    },
}

ipv4_version = "0800"
ipv4_head_length = "45"
ipv4_dsfield = "00"
ipv4_totallength = "0000"
ipv4_if = "abcd"
ipv4_fragment = "0000"
ipv4_livetime = "01"
ipv4_protocol = "11"
ipv4_headcheck = "0000"
ipv4_src_ip = "0a0a0107"
ipv4_dst_ip = "0a0a0108"

pkt_ipv4_head = (ipv4_version + ipv4_head_length + ipv4_dsfield + ipv4_totallength +
             ipv4_if + ipv4_fragment + ipv4_livetime + ipv4_protocol + ipv4_headcheck +
             ipv4_src_ip + ipv4_dst_ip)

ipv4_head = {
    "negotiation" : {
        "ipv4_version": "0800",
        "ipv4_head_length" : "45",
        "ipv4_dsfield" : "00",
        "ipv4_totallength" : "0000",
        "ipv4_if" : "abcd",
        "ipv4_fragment" : "0000",
        "ipv4_livetime" : "01",
        "ipv4_protocol" : "11",
        "ipv4_headcheck" : "0000",
        "ipv4_src_ip" : "0a0a0107",
        "ipv4_dst_ip" : "0a0a0108",
    },
}

channel_dst_mac = "ffffffffffff"
channel_src_mac = "ffffffffffff"
channel_protocol = "1000"
channel_seq = "0000"
channel_dst_chip_ip = "01"
channel_dst_mode_ip = "cc"
channel_src_chip_ip = "01"
channel_src_mode_ip = "cc"

pkt_channel_head = (channel_dst_mac + channel_src_mac + channel_protocol + channel_seq + channel_dst_chip_ip + channel_dst_mode_ip +
                    channel_src_chip_ip + channel_src_mode_ip + hexbytes_2_str(cur_seq.to_bytes(12,byteorder='big')))

channel_head = {
    "negotiation" : {
        "dst_mac" : "ffffffffffff",
        "src_mac" : "ffffffffffff",
        "protocol" : "1000",
        "seq" : "0000",
        "dst_chip_id" : "01",
        "dst_mode_id" : "cc",
        "src_chip_id" : "02",
        "src_mode_id" : "cc",
    },
}

class pkt_class:
    dst_mac = "ffffffffffff"
    src_mac = "010203040506"
    dst_chip_id = "01"
    dst_mode_id = "cc"
    src_chip_id = "01"
    src_mode_id = "cc"
    protocol = "1000"
    seq = "00000000"
    data = ""
    head_pkt = b''
    whole_pkt = b''
    def __init__(self,dst_mac,src_mac,data):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.data = data
    def set_whole_pkt(self,whole_pkt):
        self.whole_pkt=whole_pkt
    def set_dst_chip_id(self,dst_chip_id):
        self.dst_chip_id=dst_chip_id
    def set_dst_mode_id(self,dst_mode_id):
        self.dst_mode_id=dst_mode_id
    def set_src_chip_id(self,src_chip_id):
        self.src_chip_id=src_chip_id
    def set_src_mode_id(self,src_mode_id):
        self.src_mode_id=src_mode_id
    def set_protocol(self,protocol):
        self.protocol=protocol
    def set_seq(self,seq):
        self.seq=seq
    def set_head_pkt(self):
        self.head_pkt = (str_2_hexbytes(self.get_dst_mac()) + str_2_hexbytes(self.get_src_mac()) + str_2_hexbytes(self.get_protocol()) +
                         str_2_hexbytes(self.get_seq()) + str_2_hexbytes(self.get_dst_chip_id()) + str_2_hexbytes(self.get_dst_mode_id()) +
                         str_2_hexbytes(self.get_src_chip_id()) + str_2_hexbytes(self.get_src_mode_id()) + cur_seq.to_bytes(12,byteorder='big'))
    def get_dst_mac(self):
        return self.dst_mac
    def get_src_mac(self):
        return self.src_mac
    def get_dst_chip_id(self):
        return self.dst_chip_id
    def get_dst_mode_id(self):
        return self.dst_mode_id
    def get_src_chip_id(self):
        return self.src_chip_id
    def get_src_mode_id(self):
        return self.src_mode_id
    def get_protocol(self):
        return self.protocol
    def get_seq(self):
        return self.seq
    def get_head_pkt(self):
        return self.head_pkt

def get_pkt_mac_head(func_name):
    # global pkt_mac_head
    pkt_mac_head = ""
    pkt_mac_head += mac_head[func_name]["mac_dst_mac"] + mac_head[func_name]["mac_src_mac"]
    return pkt_mac_head

def get_pkt_ipv4_head(func_name):
    # global pkt_ipv4_head
    pkt_ipv4_head = ""
    pkt_ipv4_head += (ipv4_head[func_name]["ipv4_version"] + ipv4_head[func_name]["ipv4_head_length"] + ipv4_head[func_name]["ipv4_dsfield"] +
                ipv4_head[func_name]["ipv4_totallength"] + ipv4_head[func_name]["ipv4_if"] + ipv4_head[func_name]["ipv4_fragment"] +
                ipv4_head[func_name]["ipv4_livetime"] + ipv4_head[func_name]["ipv4_protocol"] + ipv4_head[func_name]["ipv4_headcheck"] +
                ipv4_head[func_name]["ipv4_src_ip"] + ipv4_head[func_name]["ipv4_dst_ip"])
    return pkt_ipv4_head

def get_pkt_channel_head(func_name):
    # global pkt_channel_head
    pkt_channel_head = ""
    pkt_channel_head += (channel_head[func_name]["dst_mac"] + channel_head[func_name]["src_mac"] + channel_head[func_name]["protocol"] +
                   channel_head[func_name]["seq"] + channel_head[func_name]["dst_chip_id"] + channel_head[func_name]["dst_mode_id"] +
                   channel_head[func_name]["src_chip_id"] + channel_head[func_name]["src_mode_id"] + cur_seq.to_bytes(12,byteorder='big'))
    return pkt_channel_head

# print(get_pkt_mac_head("negotiation"))
# print(pkt_mac_head)