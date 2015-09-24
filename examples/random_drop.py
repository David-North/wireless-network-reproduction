# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert.macdivert import MacDivert, Handle
from macdivert.enum import Flags
from impacket import ImpactDecoder
from random import random
import signal

__author__ = 'huangyan13@baidu.com'


libdivert = MacDivert()

divert_handle = None


def int_handler(signum, frame):
    if divert_handle:
        print divert_handle.stats()
        divert_handle.close()


def work():
    global divert_handle
    signal.signal(signal.SIGINT, int_handler)
    with Handle(libdivert, 0, "ip from any to any via en0",
                Flags.DIVERT_FLAG_WITH_PKTAP, -1) as fid:
        # save the fid
        if not divert_handle:
            divert_handle = fid
        while not fid.eof:
            packet = fid.read()
            if packet.flag != 0:
                print "error code is: %d" % packet.flag
            if packet.valid and not fid.eof:
                if packet.pktap and packet.pktap.pth_comm[0:5] == 'acweb':
                    if random() < 0.9:
                        fid.write(packet)
                else:
                    fid.write(packet)


if __name__ == '__main__':
    work()
