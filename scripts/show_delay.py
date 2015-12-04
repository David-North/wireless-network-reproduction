import socket
import struct
import time
from thread import start_new_thread
from time import sleep

num_send = 0
num_recv = 0


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


address = (get_ip_address(), 31500)


def server_thread_func():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    global num_send
    while True:
        sock.sendto(struct.pack(">d", time.time()), address)
        num_send += 1
        sleep(0.05)
    sock.close()


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(address)
    start_new_thread(server_thread_func, ())
    while True:
        try:
            data, addr = s.recvfrom(2048)
            num_recv += 1
            for i in xrange(0, len(data), 8):
                recv_time = time.time()
                send_time = struct.unpack(">d", data[i:i + 8])
                print 'Delay: %.3f ms' % ((recv_time - send_time[0]) * 1000)
        except:
            print 'Send: %d, received:%d' % (num_send, num_recv)
            exit(0)
    s.close()
