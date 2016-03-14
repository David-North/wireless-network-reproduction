# encoding: utf8
__author__ = 'huangyan13@baidu.com'


class Defaults(object):
    SOCKET_ADDR_SIZE = 16
    DIVERT_ERRBUF_SIZE = 256
    IPFW_RULE_SIZE = 192


class Flags(object):
    """
    refer to divert.h
    """
    DIVERT_FLAG_TCP_REASSEM = 1
