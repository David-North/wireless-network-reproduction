# encoding: utf8

import os
import sys
sys.path.append(os.getcwd())
from macdivert import MacDivert, DivertHandle
from impacket import ImpactDecoder, ImpactPacket
from signal import SIGINT, signal
import random
import socket

__author__ = 'huangyan13@baidu.com'


def work(rate):
    libdivert = MacDivert()
    ip_decoder = ImpactDecoder.IPDecoder()
    with DivertHandle(libdivert, 0, "tcp from any to any via en0") as fid:
        # register stop loop signal
        signal(SIGINT, lambda x, y: fid.close())
        while not fid.closed:
            try:
                divert_packet = fid.read(timeout=0.5)
            except:
                continue
            if divert_packet.valid:
                # decode the IP packet
                ip_packet = ip_decoder.decode(divert_packet.ip_data)
                if ip_packet.get_ip_p() == socket.IPPROTO_TCP:
                    # extract the TCP packet
                    tcp_packet = ip_packet.child()
                    # extract the payload
                    payload = tcp_packet.get_data_as_string()
                    # if there is payload of this TCP packet
                    if len(payload) > 0 and random.random() < rate:
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
                        divert_packet.ip_data = ip_packet.get_packet()
                if not fid.closed:
                    fid.write(divert_packet)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: python modify_packet.py <modify_rate>'
    else:
        work(float(sys.argv[1]))
