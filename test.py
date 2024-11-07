from scapy.all import *
from struct import *
from threading import Thread

# import util

src_mac = b'\x01\x02\x03\x04\x05\x06'
# src_mac = b'\x010203040506'
dst_mac = b'\x00\x50\x56\xC0\x00\x08'
src_id = b'\x06\x00'
dst_id = b'\x06\x00'
opt_code = b'\x01'
protoctl = b'\x10\x00'

cur_seq = 0

pkt_head = dst_mac + src_mac + protoctl + cur_seq.to_bytes(2,byteorder='big')
pkt_id = dst_id + src_id + cur_seq.to_bytes(12,byteorder='big')
pkt_data = opt_code + cur_seq.to_bytes(15,byteorder='big')
whole_pkt = pkt_head + pkt_id + pkt_data
# whole_pkt = util.hexstr_2_hex("aaaa1122223344")
# print(whole_pkt)

def print_str(str):
    print(str)

def hex_dump(data):
    for i in range(0,len(data)):
        if i % 16 == 0 and i != 0:
            print('')
        print('%02x '%data[i],end='')
    print('')

def send_pkt(threadName,whole_pkt) :
    # print(whole_pkt)
    hex_dump(whole_pkt)
    sendp(whole_pkt,iface='ens33')

def rev_socket(threadName,name):
    packet = sniff(iface='VMware Network Adapter VMnet8',count=1)
    print("get pkt\n")
    print(packet.hexdump())
    # hex_dump(packet)

if __name__ == '__main__':
    # # thread1 = Thread(target=rev_socket,args=("Thread-rev", 'a'))
    # thread2 = Thread(target=send_pkt,args=("Thread-rev", whole_pkt))
    # try:
    #     # thread1.start()
    #     thread2.start()
    # except:
    #     print ("Error: 无法启动线程")
    while True:
        send_pkt('test',whole_pkt)
