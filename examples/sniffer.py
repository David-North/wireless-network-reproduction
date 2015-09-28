# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert.macdivert import MacDivert, Handle
from macdivert.enum import Flags
from impacket import ImpactDecoder
from signal import SIGINT

__author__ = 'huangyan13@baidu.com'


def work():
    libdivert = MacDivert()
    decoder = ImpactDecoder.IPDecoder()
    with Handle(libdivert, 0, "ip from any to any",
                Flags.DIVERT_FLAG_WITH_PKTAP, -1) as fid:
        # register stop loop signal
        fid.set_stop_signal(SIGINT)
        while not fid.eof:
            packet = fid.read()
            if packet.valid:
                if fid.is_inbound(packet.sockaddr):
                    print 'packet is in bound:'
                elif fid.is_outbound(packet.sockaddr):
                    print 'packet is out bound:'
                else:
                    print 'impossible packet!'
                print decoder.decode(packet.packet)
            elif packet.flag != 0:
                print "error code is: %d" % packet.flag
            if packet.valid and not fid.eof:
                fid.write(packet)


if __name__ == '__main__':
    work()
