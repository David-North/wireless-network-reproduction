# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert import MacDivert, DivertHandle
from random import random
from signal import SIGINT, signal

__author__ = 'huangyan13@baidu.com'


def work(pid, rate):
    num_total = 0
    num_dropped = 0
    num_with_pid = 0
    libdivert = MacDivert()
    with DivertHandle(libdivert, 0, "ip from any to any in via en0") as fid:
        # register stop loop signal
        signal(SIGINT, lambda x, y: fid.close())
        while not fid.closed:
            try:
                packet = fid.read(timeout=0.5)
            except:
                continue
            if packet.valid:
                num_total += 1
                if packet.proc and packet.proc.pid != -1:
                    num_with_pid += 1

            if packet.valid and not fid.closed:
                if packet.proc and packet.proc.pid == pid:
                    if random() > rate:
                        fid.write(packet)
                    else:
                        num_dropped += 1
                else:
                    fid.write(packet)

        print "Packets total: %d" % num_total
        print "Packets with process info: %d" % num_with_pid
        print "Packets dropped: %d" % num_dropped
        print "Accuracy: %f" % (float(num_with_pid) / num_total)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Usage: python random_drop.py <pid> <drop_rate>'
    else:
        work(int(sys.argv[1]), float(sys.argv[2]))
