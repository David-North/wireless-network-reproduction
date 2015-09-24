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
    DIVERT_FLAG_BLOCK_IO=(1 << 2),
    DIVERT_FLAG_TCP_REASSEM=(1 << 3)
)

Dump_flags = enum(
    DIVERT_DUMP_BPF_HERDER=1,
    DIVERT_DUMP_PKTAP_HERDER=(1 << 1),
    DIVERT_DUMP_ETHER_HERDER=(1 << 2),
    DIVERT_DUMP_IP_HEADER=(1 << 3),
)

"""
#define DIVERT_READ_EOF             (-1)
#define DIVERT_READ_UNKNOWN_FLAG    (-2)
#define DIVERT_RAW_BPF_PACKET       (1u)
#define DIVERT_RAW_IP_PACKET        (1u << 1)
#define DIVERT_ERROR_BPF_INVALID    (1u << 2)
#define DIVERT_ERROR_BPF_NODATA     (1u << 3)
#define DIVERT_ERROR_DIVERT_NODATA  (1u << 4)
#define DIVERT_STOP_LOOP            (1u << 5)
#define DIVERT_ERROR_KQUEUE         (1u << 6)
"""
Read_stats = enum(
    DIVERT_READ_EOF=-1,
    DIVERT_READ_UNKNOWN_FLAG=-2,
    DIVERT_RAW_BPF_PACKET=1,
    DIVERT_RAW_IP_PACKET=(1 << 1),
    DIVERT_ERROR_BPF_INVALID=(1 << 2),
    DIVERT_ERROR_BPF_NODATA=(1 << 3),
    DIVERT_ERROR_DIVERT_NODATA=(1 << 4),
    DIVERT_STOP_LOOP=(1 << 5),
    DIVERT_ERROR_KQUEUE=(1 << 6),
)
