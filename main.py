# encoding: utf8

from macdivert import MacDivert, Handle
from impacket import ImpactDecoder
from enum import Flags
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
    with Handle(libdivert, 0, "tcp from any to any",
                Flags.DIVERT_FLAG_BLOCK_IO | Flags.DIVERT_FLAG_WITH_PKTAP) as fid:
        # save the fid
        if not divert_handle:
            divert_handle = fid
        for i in range(0, 1000):
            packet = fid.read()
            if fid.is_active:
                fid.write(packet)
                print decoder.decode(packet.packet)
            else:
                break


if __name__ == '__main__':
    work()
