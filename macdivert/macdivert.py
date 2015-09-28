# encoding: utf8

import os
from copy import deepcopy
from ctypes import cdll
from enum import Defaults, Flags, Read_stats
from ctypes import POINTER, pointer, cast
from ctypes import (c_uint, c_void_p, c_uint32, c_char_p, ARRAY, c_uint64, c_int16, c_int,
                    create_string_buffer, c_uint8, c_ulong, c_long, c_longlong, c_ushort)
from models import PktapHeader, IpHeader, PacketHeader, PcapStat

__author__ = 'huangyan13@baidu.com'


class MacDivert:
    divert_argtypes = {
        # divert functions
        "divert_create": [c_int, c_uint32, c_char_p],
        "divert_activate": [c_void_p, c_char_p],
        "divert_set_filter": [c_void_p, c_char_p, c_char_p],
        "divert_loop": [c_void_p, c_int],
        "divert_is_looping": [c_void_p],
        "divert_loop_stop": [c_void_p],
        "divert_bpf_stats": [c_void_p, POINTER(PcapStat)],
        "divert_read": [c_void_p, c_char_p, c_char_p, c_char_p],
        "divert_reinject": [c_void_p, c_char_p, c_int, c_char_p],
        "divert_close": [c_void_p, c_char_p],
        "divert_is_inbound": [c_char_p, c_void_p],
        "divert_is_outbound": [c_char_p],
        "divert_set_signal_handler": [c_int, c_void_p, c_void_p],
        "divert_signal_handler_stop_loop": [c_int, c_void_p],

        # util functions
        "divert_dump_packet": [c_char_p, POINTER(PacketHeader), c_uint32, c_char_p],

        # note that we use char[] to store the ipfw rule for convenience
        # although the type is mismatched, the length of pointer variable is the same
        # so this would work
        "ipfw_compile_rule": [c_char_p, c_ushort, c_char_p, c_char_p],
        "ipfw_print_rule": [c_char_p],
    }

    divert_restypes = {
        "divert_create": c_void_p,
        "divert_activate": c_int,
        "divert_set_filter": c_int,
        "divert_loop": None,
        "divert_is_looping": c_int,
        "divert_loop_stop": None,
        "divert_bpf_stats": c_int,
        "divert_read": c_long,
        "divert_reinject": c_long,
        "divert_close": c_int,
        "divert_is_inbound": c_int,
        "divert_is_outbound": c_int,
        "divert_set_signal_handler": c_int,
        "divert_signal_handler_stop_loop": None,

        "divert_dump_packet": c_char_p,
        "ipfw_compile_rule": c_int,
        "ipfw_print_rule": None,
    }

    def __init__(self, lib_path='', encoding='utf-8'):
        """
        Constructs a new driver instance
        :param lib_path: The OS path where to load the libdivert.so
        :param encoding: The character encoding to use (defaults to UTF-8)
        :return:
        """
        if not (lib_path and os.path.exists(lib_path) and os.path.isfile(lib_path)):
            lib_path = self._find_lib()
            if not lib_path:
                raise RuntimeError("Unable to find libdivert.so")

        self.dll_path = lib_path
        self.encoding = encoding
        self._load_lib(lib_path)

    @staticmethod
    def _find_lib():
        module_path = os.sep.join(__file__.split(os.sep)[0:-1])
        return os.path.join(module_path, 'libdivert.so')

    def _load_lib(self, lib_path):
        """
        Loads the libdivert library, and configuring its arguments type
        :param lib_path: The OS path where to load the libdivert.so
        :return: None
        """
        self._lib = cdll.LoadLibrary(lib_path)
        if not hasattr(self._lib, "divert_create"):
            raise RuntimeError("Not a valid libdivert library")

        # set the types of parameters
        for func_name, argtypes in self.divert_argtypes.items():
            setattr(getattr(self._lib, func_name), "argtypes", argtypes)

        # set the types of return value
        for func_name, restype in self.divert_restypes.items():
            setattr(getattr(self._lib, func_name), "restype", restype)

    def get_reference(self):
        """
        Return a reference to the internal dylib
        :return: The dylib object
        """
        return self._lib

    def open_handle(self, port=0, filter_str="", flags=0, count=-1):
        """
        Return a new handle already opened
        :param port: the port number to be diverted to, use 0 to auto select a unused port
        :param filter_str: the filter string
        :param flags: choose different mode
        :param count: how many packets to divert, negative number means unlimited
        :return: An opened Handle instance
        """
        return Handle(self, port, filter_str, flags, count, self.encoding).open()


class Handle:
    def __init__(self, libdivert=None, port=0, filter_str="", flags=0, count=-1, encoding='utf-8'):
        if not libdivert:
            # Try to construct by loading from the library path
            self._libdivert = MacDivert()
        else:
            self._libdivert = libdivert
        # buffer to store packet data
        self._ip_packet = create_string_buffer(Defaults.PACKET_BUFFER_SIZE)
        # buffer to store pktap header
        self._pktap_header = create_string_buffer(Defaults.PKTAP_SIZE)
        # buffer to store socket address
        self._sockaddr = create_string_buffer(Defaults.SOCKET_ADDR_SIZE)

        # buffer to store error message
        self._errmsg = create_string_buffer(Defaults.ERROR_MSG_SIZE)
        self._lib = self._libdivert.get_reference()
        self._port = port
        self._count = count
        self._filter = filter_str.encode(encoding)
        self._flags = flags
        self.encoding = encoding
        # create divert handle
        self._handle = self._lib.divert_create(self._port,
                                               self._flags | Flags.DIVERT_FLAG_BLOCK_IO,
                                               self._errmsg)
        self._cleaned = True
        # create active flag
        self.active = False

    def __del__(self):
        if not self._cleaned:
            self._cleaned = True
            # free close the divert handle
            if self._lib.divert_close(self._handle, self._errmsg) != 0:
                raise RuntimeError(self._errmsg.value)

    def ipfw_compile_rule(self, rule_str, port):
        rule_data = create_string_buffer(Defaults.IPFW_RULE_SIZE)
        if self._lib.ipfw_compile_rule(rule_data, port, rule_str, self._errmsg) != 0:
            raise RuntimeError("Error rule: %s" % self._errmsg.value)
        return rule_data[0:Defaults.IPFW_RULE_SIZE]

    def ipfw_print_rule(self, rule_data):
        self._lib.ipfw_print_rule(rule_data)

    @property
    def eof(self):
        if self.active:
            if self._lib.divert_is_looping(self._handle) == 0:
                self.active = False
                return True
            else:
                return False
        else:
            return True

    @property
    def closed(self):
        return not self.active

    def open(self):
        if self._lib.divert_activate(self._handle, self._errmsg) != 0:
            raise RuntimeError(self._errmsg.value)
        self.active = True
        self._cleaned = False

        if self._filter:
            self.set_filter(self._filter)

        self._lib.divert_loop(self._handle, self._count)

        return self

    def close(self):
        if self.active:
            # stop the event loop
            self._lib.divert_loop_stop(self._handle)
            self.active = False

    def set_filter(self, filter_str):
        if not self.eof and filter_str:
            if self._lib.divert_set_filter(self._handle,
                                           filter_str,
                                           self._errmsg) != 0:
                raise RuntimeError("Error rule: %s" % self._errmsg.value)
            else:
                return True
        else:
            return False

    def read(self):
        status = self._lib.divert_read(self._handle,
                                       self._pktap_header,
                                       self._ip_packet,
                                       self._sockaddr)
        ret_val = Packet()
        if status == 0:
            # try to extract the PKTAP header
            ptr_pktap = cast(self._pktap_header, POINTER(PktapHeader))
            if ptr_pktap[0].pth_length > 0:
                ret_val.pktap = deepcopy(ptr_pktap[0])

            # check if IP header is legal
            ptr_packet = cast(self._ip_packet, POINTER(IpHeader))
            header_len = ptr_packet[0].get_header_length()
            packet_length = ptr_packet[0].get_total_length()
            if packet_length > 0 and header_len > 0:
                ret_val.packet = self._ip_packet[0:packet_length]

            # save the sockaddr for re-inject
            ret_val.sockaddr = self._sockaddr[0:Defaults.SOCKET_ADDR_SIZE]
            ret_val.valid = True
        else:
            ret_val.flag = status
            ret_val.valid = False

        return ret_val

    def write(self, packet_obj):
        if self.eof:
            raise RuntimeError("Divert handle EOF.")

        if not packet_obj or not packet_obj.sockaddr or not packet_obj.packet:
            raise RuntimeError("Invalid packet data.")

        return self._lib.divert_reinject(self._handle, packet_obj.packet, -1, packet_obj.sockaddr)

    def stats(self):
        if self._cleaned:
            raise RuntimeError("Divert handle is not allocated.")

        statics_info = PcapStat()
        status = self._lib.divert_bpf_stats(self._handle, pointer(statics_info))
        if status != 0:
            return None
        else:
            return statics_info

    def is_inbound(self, sockaddr):
        return self._lib.divert_is_inbound(sockaddr, None) != 0

    def is_outbound(self, sockaddr):
        return self._lib.divert_is_outbound(sockaddr) != 0

    def set_stop_signal(self, signum):
        return self._lib.divert_set_signal_handler(
            signum, self._lib.divert_signal_handler_stop_loop, self._handle
        )

    # Context Manager protocol
    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()


class Packet:
    def __init__(self):
        self.pktap = None
        self.packet = None
        self.sockaddr = None
        self.valid = False
        self.flag = 0

    def __setitem__(self, key, value):
        if key == 'pktap':
            self.pktap = value
        elif key == 'packet':
            self.packet = value
        elif key == 'sockaddr':
            self.sockaddr = value
        elif key == 'flag':
            self.flag = value
        else:
            raise KeyError("No suck key: %s" % key)

    def __getitem__(self, item):
        if item == 'pktap':
            return self.pktap
        elif item == 'packet':
            return self.packet
        elif item == 'sockaddr':
            return self.sockaddr
        elif item == 'flag':
            return self.flag
        else:
            return None
