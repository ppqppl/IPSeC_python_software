import sys
from threading import Thread

sys.path.append("./rev")
from rev_pkt import *

def threads_start():
    thread1 = Thread(target=rev_socket_1000,args=("Thread-rev",))
    # thread2 = Thread(target=send_pkt,args=("Thread-rev", whole_pkt))
    try:
        thread1.start()
        # thread2.start()
    except:
        print ("Error: 无法启动线程")

threads_start()