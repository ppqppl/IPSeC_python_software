from scapy.all import *
import sys

from scapy.layers.l2 import ARP, Ether

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')

from utils import *

cur_seq = 0

class arp_pkt:
    mgnt_cue_seq = 0
    mgnt_dmac = "00:00:00:00:00:00"
    mgnt_smac = "00:00:00:00:00:11"
    mgnt_dchip_id = "00"
    mgnt_dmode_id = "04"
    mgnt_schip_id = "00"
    mgnt_smode_id = "cc"
    mgnt_protocol = "0100"
    op_code = 1 # 1 who-has，2 is-at
    dst_ip = "192.168.5.5"
    src_ip = "192.168.5.6"
    dst_mac = "00:00:00:00:00:01"
    src_mac = "00:00:00:00:00:02"
    mgnt_head = b''
    mgnt_dma_head = b''
    arp_whole_pkt= b''
    whole_pkt = b''


    def __init__(self,dst_ip,src_ip,dst_mac,src_mac,dst_chip,op_code):
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.op_code = 1 if op_code == "who_has" else 2
        if dst_chip == "m300":
            self.mgnt_dchip_id = "11"
            self.mgnt_dmode_id = "14"
        elif dst_chip == "fei":
            self.mgnt_dchip_id = "00"
            self.mgnt_dmode_id = "04"

    def config_mgnt_head(self):
        self.mgnt_head = (str_2_hexbytes(macstr_2_str(self.mgnt_dmac)) + get_mac_address() + str_2_hexbytes("1000") + self.mgnt_cue_seq.to_bytes(2,byteorder='big'))
        return self.mgnt_head

    def config_mgnt_dma_head(self):
        blank = 0
        self.mgnt_dma_head = (str_2_hexbytes(self.mgnt_dchip_id) + str_2_hexbytes(self.mgnt_dmode_id) + str_2_hexbytes(self.mgnt_schip_id) +
                               str_2_hexbytes(self.mgnt_smode_id) + blank.to_bytes(12,byteorder='big'))
        return self.mgnt_dma_head

    def get_arp_requair_whole_pkt(self):
        arp_request = ARP(pdst = self.dst_ip,psrc = self.src_ip,hwdst = self.dst_mac,hwsrc = self.src_mac,op = self.op_code)
        ether_frame = Ether(dst=self.dst_mac, src=self.src_mac)
        arp_request.show()
        self.arp_whole_pkt = bytes(ether_frame / arp_request)
        return self.arp_whole_pkt

    def config_whole_pkt(self):
        # hex_dump(self.arp_whole_pkt)
        self.whole_pkt = self.config_mgnt_head() + self.config_mgnt_dma_head() + self.get_arp_requair_whole_pkt()
        # print(self.whole_pkt)
        return self.whole_pkt

def get_mac_address():
    mac = uuid.UUID(int = uuid.getnode())
    mac_str = str(mac).split('-')[-1]
    res = bytes()
    for i in range(0,6):
        res += (int(mac_str[i*2:i*2+2],16)).to_bytes(1,byteorder='big')
    return res

def set_arp_pkt(dst_ip,src_ip,dst_mac,src_mac,dst_chip,op_code):
    arp_pkt_obj = arp_pkt(dst_ip,src_ip,dst_mac,src_mac,dst_chip,op_code)
    send_arp(arp_pkt_obj)

def send_arp(arp_pkt_obj):
    whole_pkt = arp_pkt_obj.config_whole_pkt()
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')

# set_arp_pkt("192.168.133.128","192.168.99.2","00:00:00:00:00:01","00:00:00:00:00:02","m300","is_at")
