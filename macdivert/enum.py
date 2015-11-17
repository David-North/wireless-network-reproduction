# encoding: utf8
__author__ = 'huangyan13@baidu.com'


def enum(**enums):
    return type('Enum', (), enums)


Defaults = enum(
    PACKET_BUFFER_SIZE=65545,
    PROC_INFO_SIZE=64,
    SOCKET_ADDR_SIZE=16,
    DIVERT_ERRBUF_SIZE=256,
    IPFW_RULE_SIZE=192,
)


# refer to divert.h
Flags = enum(
    DIVERT_FLAG_FAST_EXIT=(1 << 1),
    DIVERT_FLAG_BLOCK_IO=(1 << 2),
    DIVERT_FLAG_TCP_REASSEM=(1 << 3)
)

"""
#define DIVERT_READ_EOF             (-1)
#define DIVERT_READ_UNKNOWN_FLAG    (-2)
#define DIVERT_RAW_IP_PACKET        (1u)
#define DIVERT_ERROR_DIVERT_NODATA  (1u << 1)
#define DIVERT_STOP_LOOP            (1u << 2)
#define DIVERT_ERROR_KQUEUE         (1u << 3)
#define DIVERT_ERROR_INVALID_IP     (1u << 4)
"""
Read_stats = enum(
    DIVERT_READ_EOF=-1,
    DIVERT_READ_UNKNOWN_FLAG=-2,
    DIVERT_RAW_IP_PACKET=1,
    DIVERT_ERROR_DIVERT_NODATA=(1 << 1),
    DIVERT_STOP_LOOP=(1 << 2),
    DIVERT_ERROR_KQUEUE=(1 << 3),
    DIVERT_ERROR_INVALID_IP=(1 << 4)
)
