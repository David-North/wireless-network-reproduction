# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert.macdivert import MacDivert, Handle
from macdivert.enum import Flags
from impacket import ImpactDecoder, ImpactPacket
import random
import signal
import socket
import re


__author__ = 'huangyan13@baidu.com'


lib_path = '/Users/baidu/Library/Caches/clion11/cmake/generated/b28c2630/b28c2630/Release/libdivert.dylib'
libdivert = MacDivert(lib_path)

divert_handle = None


def int_handler(signum, frame):
    if divert_handle:
        print divert_handle.stats()
        divert_handle.close()


def work():
    pattern = re.compile("compiler", re.IGNORECASE)
    global divert_handle
    ip_decoder = ImpactDecoder.IPDecoder()
    tcp_decoder = ImpactDecoder.TCPDecoder()
    signal.signal(signal.SIGINT, int_handler)
    with Handle(libdivert, 0, "tcp from any to any via en0",
                Flags.DIVERT_FLAG_WITH_PKTAP, -1) as fid:
        # save the fid
        if not divert_handle:
            divert_handle = fid
        while not fid.eof:
            divert_packet = fid.read()
            if divert_packet.valid and not fid.eof:
                # decode the IP packet
                ip_packet = ip_decoder.decode(divert_packet.packet)
                if ip_packet.get_ip_p() == socket.IPPROTO_TCP:
                    # extract the TCP packet
                    tcp_packet = ip_packet.child()
                    # extract the payload
                    payload = tcp_packet.get_data_as_string()
                    # if there is payload of this TCP packet
                    if len(payload) > 0 and random.random() < 0.05:
                        # modify one byte of the packet
                        modify_pos = random.randint(0, len(payload) - 1)
                        payload = payload[0:modify_pos] + '\x02' + payload[modify_pos + 1:]
                        # create Data object with modified data
                        new_data = ImpactPacket.Data(payload)
                        # replace the payload of TCP packet with new Data object
                        tcp_packet.contains(new_data)
                        # update the packet checksum
                        tcp_packet.calculate_checksum()
                        # replace the payload of IP packet with new TCP object
                        ip_packet.contains(tcp_packet)
                        # update the packet checksum
                        ip_packet.calculate_checksum()
                        # finally replace the raw data of diverted packet with modified one
                        divert_packet.packet = ip_packet.get_packet()
                fid.write(divert_packet)


if __name__ == '__main__':
    work()
