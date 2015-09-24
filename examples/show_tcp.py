# encoding: utf8

import os
import sys

sys.path.append(os.getcwd())
from macdivert.macdivert import MacDivert, Handle
from macdivert.enum import Flags
from copy import deepcopy
import signal
from macdivert import libdivert as nids

__author__ = 'huangyan13@baidu.com'

divert_file = MacDivert()

divert_handle = None

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)


def int_handler(signum, frame):
    if divert_handle:
        print divert_handle.stats()
        divert_handle.close()


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
    global divert_handle
    signal.signal(signal.SIGINT, int_handler)
    with Handle(divert_file, 0, "ip from any to any",
                Flags.DIVERT_FLAG_WITH_PKTAP |
                        Flags.DIVERT_FLAG_TCP_REASSEM, -1) as fid:

        nids.register_tcp(tcp_callback)

        # save the fid
        if not divert_handle:
            divert_handle = fid
        # register TCP callback function
        while not fid.eof:
            packet = fid.read()
            if packet.valid and not fid.eof:
                fid.write(packet)


if __name__ == '__main__':
    work()
