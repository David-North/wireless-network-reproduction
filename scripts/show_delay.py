import sys
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
        data = struct.pack("<l", num_send) + \
               struct.pack("<d", time.time()) + \
               '-' * (num_send % 30 + 1)
        sock.sendto(data, address)
        num_send += 1
        sleep(0.05)
    sock.close()


def main():
    global num_recv
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(address)
    start_new_thread(server_thread_func, ())
    while True:
        try:
            data, addr = s.recvfrom(2048)
            num_recv += 1
            recv_time = time.time()
            send_time = struct.unpack("<d", data[4:12])
            idx = struct.unpack("<l", data[0:4])[0]
            print 'No.%3d %.2fms %s' % (idx, (recv_time - send_time[0]) * 1000, data[12:])
        except:
            print 'Send: %d, received:%d' % (num_send, num_recv)
            sys.exit(0)
    s.close()

if __name__ == '__main__':
    main()
