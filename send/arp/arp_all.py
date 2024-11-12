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
    mgnt_dmode_id = "00"
    mgnt_schip_id = "00"
    mgnt_smode_id = "00"
    mgnt_protocol = "0100"
    dst_ip = "192.168.5.5"
    src_ip = "192.168.5.6"
    dst_mac = "00:00:00:00:00:01"
    src_mac = "00:00:00:00:00:02"
    mgnt_head = b''
    arp_whole_pkt= b''


    def __init__(self,dst_ip,src_ip,dst_mac,src_mac):
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.src_mac = src_mac

    # def config_mgnt_head(self):


    def get_arp_requair_whole_pkt(self):
        arp_request = ARP(pdst = self.dst_ip,psrc = self.src_ip,hwdst = self.dst_mac,hwsrc = self.src_mac)
        ether_frame = Ether(dst=self.dst_mac, src=self.src_mac)
        arp_request.show()
        self.arp_whole_pkt = bytes(ether_frame / arp_request)
        return self.arp_whole_pkt

def send_sad(sad_pkt_obj):
    whole_pkt = sad_pkt_obj.whole_pkt
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')

a = arp_pkt("192.168.133.128","192.168.99.2","00:00:00:00:00:01","00:00:00:00:00:02")

    # a.get_arp_requair_whole_pkt()
sendp(a.get_arp_requair_whole_pkt(),iface='VMware Network Adapter VMnet8')