from scapy.all import *
import sys

sys.path.append('../')
sys.path.append('../../')
sys.path.append('../../utils')

from utils import *
from send_pkt import *

cur_seq = 0

class sad_pkt:
    op_code = "ADD"
    dst_mac = "08:11:22:33:44:ab"
    dst_chip_id = "06"
    dst_mode_id = "02"
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
    sa_op_code = 0 # 1-Direct; 2-Drop; 3-Encryption
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
    firewall_protocol = "UDP"
    def __init__(self,dst_mode,opcode,tunnel_dip,tunnel_sip):
        print("create ok")

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

def send_sad(whole_pkt):
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')
