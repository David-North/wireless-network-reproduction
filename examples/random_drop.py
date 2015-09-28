# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert.macdivert import MacDivert, Handle
from macdivert.enum import Flags
from random import random
from signal import SIGINT

__author__ = 'huangyan13@baidu.com'


def work(pid, rate):
    num_total = 0
    num_dropped = 0
    num_with_pktap = 0
    libdivert = MacDivert()
    with Handle(libdivert, 0, "ip from any to any in via en0",
                Flags.DIVERT_FLAG_WITH_PKTAP, -1) as fid:
        # register stop loop signal
        fid.set_stop_signal(SIGINT)
        while not fid.eof:
            packet = fid.read()
            if packet.valid:
                num_total += 1
                if packet.pktap and packet.pktap.pth_pid != -1:
                    num_with_pktap += 1

            if packet.valid and not fid.eof:
                if packet.pktap and packet.pktap.pth_pid == pid:
                    if random() < 1 - rate:
                        fid.write(packet)
                    else:
                        num_dropped += 1
                else:
                    fid.write(packet)

        print "Packets total: %d" % num_total
        print "Packets with PKTAP info: %d" % num_with_pktap
        print "Packets dropped: %d" % num_dropped
        print "Accuracy: %f" % (float(num_with_pktap) / num_total)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Usage: python random_drop.py <pid> <drop_rate>'
    else:
        work(int(sys.argv[1]), float(sys.argv[2]))
