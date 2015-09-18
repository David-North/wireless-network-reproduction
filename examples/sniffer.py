# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert.macdivert import MacDivert, Handle
from macdivert.enum import Flags
from impacket import ImpactDecoder
import signal

__author__ = 'huangyan13@baidu.com'


lib_path = '/Users/baidu/Library/Caches/clion11/cmake/generated/b28c2630/b28c2630/Release/libdivert.dylib'
libdivert = MacDivert(lib_path)

divert_handle = None


def int_handler(signum, frame):
    if divert_handle:
        print divert_handle.stats()
        divert_handle.close()


def work():
    global divert_handle
    decoder = ImpactDecoder.IPDecoder()
    signal.signal(signal.SIGINT, int_handler)
    with Handle(libdivert, 0, "ip from any to any", Flags.DIVERT_FLAG_WITH_PKTAP, -1) as fid:
        # save the fid
        if not divert_handle:
            divert_handle = fid
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
            else:
                print "error code is: %d" % packet.flag
            if packet.valid and not fid.eof:
                fid.write(packet)


if __name__ == '__main__':
    work()
