import socket
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
    idx = 0
    global num_send
    while True:
        sock.sendto('-' * (idx % 50 + 1), address)
        num_send += 1
        idx += 1
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
            print data
        except:
            print 'Send: %d, received:%d' % (num_send, num_recv)
            exit(0)
    s.close()
