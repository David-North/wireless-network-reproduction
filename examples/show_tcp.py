# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert import MacDivert, DivertHandle
from macdivert.enum import Flags
from macdivert import nids
from signal import SIGINT, signal

__author__ = 'huangyan13@baidu.com'

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)


def tcp_callback(tcp):
    print "tcps -", str(tcp.addr), " state:", tcp.nids_state
    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new to us, but do we care?
        ((src, sport), (dst, dport)) = tcp.addr
        print tcp.addr
        if dport in (80, 8000, 8080):
            print "collecting..."
            tcp.client.collect = 1
            tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
        tcp.discard(0)
    elif tcp.nids_state in end_states:
        print "addr:", tcp.addr
        print "To server:"
        print tcp.server.data[:tcp.server.count]  # WARNING - may be binary
        print "To client:"
        print tcp.client.data[:tcp.client.count]  # WARNING - as above


def work():
    # init libnids library
    nids.init()
    divert_file = MacDivert()
    with DivertHandle(divert_file, 0, "ip from any to any via en0",
                      Flags.DIVERT_FLAG_TCP_REASSEM) as fid:
        # register stop loop signal
        signal(SIGINT, lambda x, y: fid.close())
        # register TCP callback function
        nids.register_tcp(tcp_callback)
        while not fid.closed:
            # read a packet and write it back
            try:
                packet = fid.read(timeout=0.5)
            except:
                continue
            if packet.valid and not fid.closed:
                fid.write(packet)


if __name__ == '__main__':
    work()
