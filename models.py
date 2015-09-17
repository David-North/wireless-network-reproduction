# encoding: utf8

from socket import ntohs
from ctypes import (c_uint, c_void_p, c_uint32, c_char_p, ARRAY, c_uint64, c_int32, c_uint16, c_int,
                    c_uint8, c_ulong, c_char, Structure)


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
    _fields_ = [
        ("bhep_hdr", c_void_p),
        ("pktap_hdr", c_void_p),
        ("ether_hdr", c_void_p),
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


class PktapHeader(Structure):
    """
    Ctypes structure for apple PKTAP header definition.
    struct pktap_header {
        uint32_t		pth_length;
        uint32_t		pth_type_next;
        uint32_t		pth_dlt;
        char			pth_ifname[PKTAP_IFXNAMESIZE];
        uint32_t		pth_flags;
        uint32_t		pth_protocol_family;
        uint32_t		pth_frame_pre_length;
        uint32_t		pth_frame_post_length;
        pid_t			pth_pid;
        char			pth_comm[MAXCOMLEN+1];
        uint32_t		pth_svc;
        uint16_t		pth_iftype;
        uint16_t		pth_ifunit;
        pid_t			pth_epid;
        char			pth_ecomm[MAXCOMLEN+1];
        uint32_t		pth_flowid;
        uint32_t		pth_ipproto;
        struct timeval32	pth_tstamp;
        uuid_t			pth_uuid;
        uuid_t			pth_euuid;
    };
    """
    MAXCOMLEN = 16
    PKTAP_IFXNAMESIZE = 24
    _fields_ = [
        ("pth_length", c_uint32),
        ("pth_type_next", c_uint32),
        ("pth_dlt", c_uint32),
        ("pth_ifname", c_char * PKTAP_IFXNAMESIZE),
        ("pth_flags", c_uint32),
        ("pth_protocol_family", c_uint32),
        ("pth_frame_pre_length", c_uint32),
        ("pth_frame_post_length", c_uint32),
        ("pth_pid", c_int32),
        ("pth_comm", c_char * (MAXCOMLEN + 1)),
        ("pth_svc", c_uint32),
        ("pth_iftype", c_uint16),
        ("pth_ifunit", c_uint16),
        ("pth_epid", c_int32),
        ("pth_ecomm", c_char * (MAXCOMLEN + 1)),
        ("pth_flowid", c_uint32),
        ("pth_ipproto", c_uint32),
        ("pth_tstamp", c_int32 * 2),
        ("pth_uuid", c_uint8 * 16),
        ("pth_euuid", c_uint8 * 16),
    ]

    def __str__(self):
        return format_structure(self)
