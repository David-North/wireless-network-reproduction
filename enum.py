# encoding: utf8
__author__ = 'huangyan13@baidu.com'


def enum(**enums):
    return type('Enum', (), enums)


Defaults = enum(
    PACKET_BUFFER_SIZE=65535,
    PKTAP_SIZE=512,
    SOCKET_ADDR_SIZE=16,
    ERROR_MSG_SIZE=256,
    IPFW_RULE_SIZE=192,
)


# refer to divert.h
Flags = enum(
    DIVERT_FLAG_WITH_PKTAP=1,
    DIVERT_FLAG_PRECISE_INFO=(1 << 1),
    DIVERT_FLAG_BLOCK_IO=(1 << 2)
)

Dump_flags = enum(
    DIVERT_DUMP_BPF_HERDER=1,
    DIVERT_DUMP_PKTAP_HERDER=(1 << 1),
    DIVERT_DUMP_ETHER_HERDER=(1 << 2),
    DIVERT_DUMP_IP_HEADER=(1 << 3),
)