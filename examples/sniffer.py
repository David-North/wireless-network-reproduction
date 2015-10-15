# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert import MacDivert, DivertHandle
from macdivert.enum import Read_stats
from impacket import ImpactDecoder
from signal import SIGINT

__author__ = 'huangyan13@baidu.com'


def work():
    libdivert = MacDivert()
    decoder = ImpactDecoder.IPDecoder()
    with DivertHandle(libdivert, 0, "ip from any to any via en0") as fid:
        pcap = fid.open_pcap('sniff.pcap')
        # register stop loop signal
        fid.set_stop_signal(SIGINT)
        while not fid.eof:
            packet = fid.read()

            if packet.valid:
                if packet.proc:
                    proc_str = '%s: %d\t' % \
                               (packet.proc.comm, packet.proc.pid)
                else:
                    proc_str = 'Unknown process\t'

                if fid.is_inbound(packet.sockaddr):
                    direct_str = 'inbound'
                elif fid.is_outbound(packet.sockaddr):
                    direct_str = 'outbound'
                else:
                    direct_str = 'impossible packet!'

                print proc_str + direct_str
                print decoder.decode(packet.ip_data)
            elif packet.flag != 0 and packet.flag != Read_stats.DIVERT_READ_EOF:
                print "error code is: %d" % packet.flag
            if packet.valid and not fid.eof:
                # re-inject the packet
                fid.write(packet)
                # save the packet into sniff.pcap
                pcap.write(packet)


if __name__ == '__main__':
    work()
