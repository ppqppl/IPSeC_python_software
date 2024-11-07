#!/usr/bin/python3
from scapy.all import *
from struct import *
import string
import uuid
import time
    
#Configure
dst_mac = b'\x08\x11\x22\x33\x44\xab'
cfg_msg_per_pkt = 5
target_id = b'\x06\x02'
source_id = b'\x06\xcc'
sa_tuples = [
    {
    'op_code' : 'ADD',
    'sa_valid' : 1,	# 1-Valid; 0-Invalid;
    'sa_index' : 0,
    'tunnel_dip' : '100.100.4.1',
    # 'tunnel_dip' : '10.10.100.6',
    'tunnel_sip' : '100.100.3.1',
    # 'tunnel_sip' : '10.10.100.233',
	'key_index' : 0x12345678,
    'sa_status' : 0, # 0-Unnegotiate; 1-Negotiating; 2-In Service;
    'sa_anti_replay' : 0, # 0-Disable anti-replay; 1-Enable anti-replay;
    'sa_type' : 0, # 0-Unicast; 1-Multicast; 2-Management; 3-Neotiation;
    'sa_op_code' : 2,# 1-Direct; 2-Drop; 3-Encryption
    'sa_packet_mtu' : 1536,
    'channel_id' : 0, # 0-Normal; 1-CPU; 2-Loop;
    'transmit_mode' : 1, # 1-Tunnel; 2-Transmission;
    'exchange_port' : 0, # 0-Disable; 1-Enable;
    'post_to_cpu' : 0, # 0-Disable; 1-Enable;
    'multicast_index' : 0,
    'alg_type' : 0,
    'firewall_dip' : '192.168.23.56',
    'firewall_sip' : '192.168.64.30',
    'firewall_dmask' : '255.255.255.255',
    'firewall_smask' : '255.255.255.255',
    'firewall_dport' : 5000,
    'firewall_sport' : 2526,
    'firewall_protocol' : 'UDP'
    }
]

##########

def get_mac_address():
    mac = uuid.UUID(int = uuid.getnode())
    mac_str = str(mac).split('-')[-1]
    res = bytes()
    for i in range(0,6):
        res += (int(mac_str[i*2:i*2+2],16)).to_bytes(1,byteorder='big')
    return res

def hex_dump(data):
    for i in range(0,len(data)):
        if i % 16 == 0 and i != 0:
            print('')
        print('%02x '%data[i],end='')
    print('')

def ip_to_bytes(ip):
    ip_item = ip.split('.')
    res = bytes()
    for s in ip_item:
        res += int(s).to_bytes(1,byteorder='big')
    return res

def op_code_to_byte(op_code):
    if op_code == 'ADD':
        return b'\x01'
    elif op_code == 'DEL':
        return b'\x02'
    elif op_code == 'CLR':
        return b'\x03'
    else:
        return b'\x00'

def protocol_to_byte(protocol):
    if protocol == 'ICMP':
        return b'\x01'
    elif protocol == 'UDP':
        return b'\x11'
    elif protocol == 'TCP':
        return b'\x06'
    elif protocol == 'ESP':
        return b'\x32'
    else:
        return b'\x00'

print('SAD Management Service V1.0.20240528\r\nLocal MAC: ',end = '')
hex_dump(get_mac_address())
total_cfg_num = len(sa_tuples)
print('Configure count: %d'%total_cfg_num)
if total_cfg_num % cfg_msg_per_pkt == 0:
    total_pkt_cnt = int(total_cfg_num / cfg_msg_per_pkt)
else:
    total_pkt_cnt = int(total_cfg_num / cfg_msg_per_pkt) + 1
print('Packet count: %d'%total_pkt_cnt)
print('Generate SAD Configure Message ...')
# hex_dump(ip_to_bytes(ip_tuples[0]['src_ip']))
cur_seq = 0
cur_tuple = 0

mgnt_dma_route_header = target_id + source_id + 12 * b'\x00'
for i in range(0,total_pkt_cnt):
    message_head = dst_mac + get_mac_address() + b'\x10\x00' + cur_seq.to_bytes(2,byteorder='big')
    messgae_load = bytes()
    if total_cfg_num - cur_tuple >= cfg_msg_per_pkt:
        msg_total_cfg_cnt = cfg_msg_per_pkt
    else:
        msg_total_cfg_cnt = total_cfg_num - cur_tuple
    cur_cfg_in_message = 0
    for k in range(cur_tuple,cur_tuple + msg_total_cfg_cnt):
        messgae_load += msg_total_cfg_cnt.to_bytes(1,byteorder='big') + cur_cfg_in_message.to_bytes(1,byteorder='big')
        messgae_load += op_code_to_byte(sa_tuples[k]['op_code'])
        messgae_load += sa_tuples[k]['sa_valid'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['sa_index'].to_bytes(4,byteorder='big')
        messgae_load += ip_to_bytes(sa_tuples[k]['tunnel_dip'])
        messgae_load += ip_to_bytes(sa_tuples[k]['tunnel_sip'])
        messgae_load += sa_tuples[k]['key_index'].to_bytes(4,byteorder='big')
        messgae_load += sa_tuples[k]['sa_status'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['sa_anti_replay'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['sa_type'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['sa_op_code'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['sa_packet_mtu'].to_bytes(2,byteorder='big')
        messgae_load += sa_tuples[k]['channel_id'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['transmit_mode'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['exchange_port'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['post_to_cpu'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['multicast_index'].to_bytes(1,byteorder='big')
        messgae_load += sa_tuples[k]['alg_type'].to_bytes(1,byteorder='big')
        messgae_load += ip_to_bytes(sa_tuples[k]['firewall_dip'])
        messgae_load += ip_to_bytes(sa_tuples[k]['firewall_sip'])
        messgae_load += ip_to_bytes(sa_tuples[k]['firewall_dmask'])
        messgae_load += ip_to_bytes(sa_tuples[k]['firewall_smask'])
        messgae_load += sa_tuples[k]['firewall_dport'].to_bytes(2,byteorder='big')
        messgae_load += sa_tuples[k]['firewall_sport'].to_bytes(2,byteorder='big')
        messgae_load += protocol_to_byte(sa_tuples[k]['firewall_protocol'])
        messgae_load += b'\x00' * 11
        cur_cfg_in_message += 1
        cur_tuple += 1
    whole_pkt = message_head + mgnt_dma_route_header + messgae_load
    print('Ethernet packet %d contant:'%(cur_seq + 1))
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='以太网')
    cur_seq += 1
        
