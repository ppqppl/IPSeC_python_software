from scapy.all import *
from struct import *
from threading import Thread

# import utils
from rev import rev_icmp
from rev import rev_tcp
from rev import rev_udp
from rev import rev_pkt

def start_thread():
    thread1 = Thread(target=rev_pkt.rev_socket_1000,args=("Thread-rev",))
    try:
        thread1.start()
    except:
        print ("Error: 无法启动线程")


if __name__ == '__main__':
    # utils.print_str("hello,let's start")
    # start_thread()
    print("start")