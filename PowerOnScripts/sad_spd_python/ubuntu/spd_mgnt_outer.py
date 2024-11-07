#!/usr/bin/python3
from scapy.all import *
from struct import *
import string
import uuid
import time
#Configure
dst_mac = b'\x08\x11\x22\x33\x44\xab'
cfg_msg_per_pkt = 5
ip_tuples = [
    {
    'op_code' : 'CLR',
    'ip_ver' : 4,
    'protocol' : 'ICMP',
    'src_ip' : '192.168.137.100',
    'src_mask' : '255.255.255.255',
	'dst_ip' : '192.168.137.64',
    'dst_mask' : '255.255.255.255',
    'src_port' : 0,
    'dst_port' : 0,
    'sa_index' : 14
    },
    # {
    # 'op_code' : 'ADD',
    # 'ip_ver' : 4,
    # 'protocol' : 'TCP',
    # 'src_ip' : '192.168.137.168',
    # 'src_mask' : '255.255.255.255',
	# 'dst_ip' : '192.168.137.73',
    # 'dst_mask' : '255.255.255.255',
    # 'src_port' : 5000,
    # 'dst_port' : 0,
    # 'sa_index' : 78
    # },
    # {
    # 'op_code' : 'ADD',
    # 'ip_ver' : 4,
    # 'protocol' : 'UDP',
    # 'src_ip' : '10.137.2.101',
    # 'src_mask' : '255.255.255.255',
	# 'dst_ip' : '10.137.4.21',
    # 'dst_mask' : '255.255.255.255',
    # 'src_port' : 3078,
    # 'dst_port' : 65306,
    # 'sa_index' : 5
    # },
    {
    'op_code' : 'ADD',
    'ip_ver' : 4,
    'protocol' : 'ESP',
    'src_ip' : ' 192.168.1.1',
    'src_mask' : '0.0.0.0',
	'dst_ip' : '192.168.3.100',
    'dst_mask' : '0.0.0.0',
    'src_port' : 0,
    'dst_port' : 0,
    'sa_index' : 1
    }
    # {
    # 'op_code' : 'ADD',
    # 'ip_ver' : 4,
    # 'protocol' : 'ESP',
    # 'src_ip' : ' 192.168.14.10',
    # 'src_mask' : '0.0.0.0',
	# 'dst_ip' : '192.168.14.20',
    # 'dst_mask' : '0.0.0.0',
    # 'src_port' : 0,
    # 'dst_port' : 0,
    # 'sa_index' : 1
    # }
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

def func():

    print('SPD Management Service V1.0\r\nLocal MAC: ',end = '')
    hex_dump(get_mac_address())
    total_cfg_num = len(ip_tuples)
    print('Configure count: %d'%total_cfg_num)
    if total_cfg_num % cfg_msg_per_pkt == 0:
        total_pkt_cnt = int(total_cfg_num / cfg_msg_per_pkt)
    else:
        total_pkt_cnt = int(total_cfg_num / cfg_msg_per_pkt) + 1
    print('Packet count: %d'%total_pkt_cnt)
    print('Generate SPD Configure Message ...')
    # hex_dump(ip_to_bytes(ip_tuples[0]['src_ip']))
    cur_seq = 0
    cur_tuple = 0
    target_id = b'\x04\x01'
    source_id = b'\x06\xcc'
    
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
            messgae_load += op_code_to_byte(ip_tuples[k]['op_code'])
            messgae_load += ip_tuples[k]['ip_ver'].to_bytes(1,byteorder='big')
            messgae_load += protocol_to_byte(ip_tuples[k]['protocol'])
            messgae_load += b'\x00'
            messgae_load += ip_tuples[k]['dst_port'].to_bytes(2,byteorder='big')
            messgae_load += ip_tuples[k]['src_port'].to_bytes(2,byteorder='big')
            messgae_load += b'\x00'*2
            messgae_load += ip_tuples[k]['sa_index'].to_bytes(4,byteorder='big')
            messgae_load += b'\x00'*12
            messgae_load += ip_to_bytes(ip_tuples[k]['dst_ip'])
            messgae_load += b'\x00'*12
            messgae_load += ip_to_bytes(ip_tuples[k]['dst_mask'])
            messgae_load += b'\x00'*12
            messgae_load += ip_to_bytes(ip_tuples[k]['src_ip'])
            messgae_load += b'\x00'*12
            messgae_load += ip_to_bytes(ip_tuples[k]['src_mask'])
            cur_cfg_in_message += 1
            cur_tuple += 1
        whole_pkt = message_head + mgnt_dma_route_header + messgae_load
        print('Ethernet packet %d contant:'%(cur_seq + 1))
        hex_dump(whole_pkt)
        sendp(whole_pkt,iface='以太网')
        cur_seq += 1
        
if __name__ == "__main__":
    
    # 循环发
    # while(True):
    #     func()
        
    # 单独发
    func()
