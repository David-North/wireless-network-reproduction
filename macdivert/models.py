# encoding: utf8

from socket import ntohs
from ctypes import (c_uint, c_void_p, c_uint32, c_char_p, ARRAY, c_uint64, c_int32, c_uint16, c_int,
                    c_uint8, c_ulong, c_char, c_ubyte, Structure, c_size_t, c_ssize_t)
from enum import Defaults


def format_structure(instance):
    """
    Returns a string representation for the structure
    """
    if hasattr(instance, "_fields_"):
        out = []
        for field in instance._fields_:
            out.append("[%s: %s]" % (field[0], getattr(instance, field[0], None)))
        return "".join(out)
    else:
        raise ValueError("Passed argument is not a structure!")


class PacketHeader(Structure):
    """
    typedef struct {
        struct ip *ip_hdr;
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;
        u_char *payload;
        size_t size_ip;
        size_t size_tcp;
        size_t size_udp;
        size_t size_payload;
    } packet_hdrs_t;
    """
    _fields_ = [
        ("ip_hdr", c_void_p),
        ("tcp_hdr", c_void_p),
        ("udp_hdr", c_void_p),
        ("payload", c_char_p),
        ("size_ip", c_ulong),
        ("size_tcp", c_ulong),
        ("size_udp", c_ulong),
        ("size_payload", c_ulong),
    ]


class IpHeader(Structure):
    """
    Ctypes structure for IPv4 header definition.
    struct ip {
        u_char	ip_vhl;			/* version << 4 | header length >> 2 */
        u_char	ip_tos;			/* type of service */
        u_short	ip_len;			/* total length */
        u_short	ip_id;			/* identification */
        u_short	ip_off;			/* fragment offset field */
        u_char	ip_ttl;			/* time to live */
        u_char	ip_p;			/* protocol */
        u_short	ip_sum;			/* checksum */
        struct	in_addr ip_src,ip_dst;	/* source and dest address */
    };
    """
    _fields_ = [
        ("ip_vhl", c_uint8),
        ("ip_tos", c_uint8),
        ("ip_len", c_uint16),
        ("ip_id", c_uint16),
        ("ip_off", c_uint16),
        ("ip_ttl", c_uint8),
        ("ip_p", c_uint8),
        ("ip_sum", c_uint16),
        ("ip_src", c_uint32),
        ("ip_dst", c_uint32),
    ]

    def get_total_length(self):
        return ntohs(self.ip_len)

    def get_header_length(self):
        return (self.ip_vhl & 0x0f) * 4

    def __str__(self):
        return format_structure(self)


class ProcInfo(Structure):
    """
    typedef struct {
        pid_t pid;
        pid_t epid;
        char comm[MAX_COMM_LEN];
    } proc_info_t;
    """
    MAXCOMLEN = 32
    _fields_ = [
        ("pid", c_int32),
        ("epid", c_int32),
        ("comm", c_char * MAXCOMLEN),
    ]

    def __str__(self):
        return format_structure(self)


class DivertHandleRaw(Structure):
    """
   typedef struct {
        u_int32_t flags;
        int divert_fd;
        int kext_fd;
        int ipfw_id;
        int divert_port;
        int pipe_fd[2];
        int exit_fd[2];
        u_char *divert_buffer;
        size_t bufsize;
        packet_buf_t *thread_buffer;
        size_t thread_buffer_size;
        u_int64_t num_unknown;
        u_int64_t num_diverted;
        divert_error_handler_t err_handler;
        divert_callback_t callback;
        void *callback_args;
        volatile u_char is_looping;
        char *ipfw_filter;
        char errmsg[DIVERT_ERRBUF_SIZE];
    } divert_t;
    """
    _fields_ = [
        ("flags", c_uint32),
        ("divert_fd", c_int),
        ("kext_fd", c_int),
        ("ipfw_id", c_int),
        ("divert_port", c_int),
        ("pipe_fd", c_int * 2),
        ("exit_fd", c_int * 2),
        ("divert_buffer", c_char_p),
        ("bufsize", c_size_t),
        ("thread_buffer", c_void_p),
        ("thread_buffer_size", c_size_t),
        ("num_unknown", c_uint64),
        ("num_diverted", c_uint64),
        ("err_handler", c_void_p),
        ("callback", c_void_p),
        ("callback_args", c_void_p),
        ("is_looping", c_ubyte),
        ("ipfw_filter", c_char_p),
        ("errmsg", c_char * Defaults.DIVERT_ERRBUF_SIZE)
    ]

    def __str__(self):
        return format_structure(self)
