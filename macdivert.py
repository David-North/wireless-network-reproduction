# encoding: utf8

import os
from copy import deepcopy
from ctypes import cdll
from ctypes import POINTER, pointer, cast
from ctypes import (c_uint, c_void_p, c_uint32, c_char_p, ARRAY, c_uint64, c_int16, c_int,
                    create_string_buffer, c_uint8, c_ulong, c_long, c_longlong)
from enum import Defaults, Flags, Dump_flags
from models import PktapHeader, IpHeader, PacketHeader

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
        "divert_read": [c_void_p, c_char_p, c_char_p, c_char_p],
        "divert_reinject": [c_void_p, c_char_p, c_int, c_char_p],
        "divert_close": [c_void_p, c_char_p],

        # util functions
        "divert_dump_packet": [c_char_p, POINTER(PacketHeader), c_uint32, c_char_p],
    }

    divert_restypes = {
        "divert_create": c_void_p,
        "divert_activate": c_int,
        "divert_set_filter": c_int,
        "divert_loop": None,
        "divert_is_looping": c_int,
        "divert_loop_stop": None,
        "divert_read": c_long,
        "divert_reinject": c_long,
        "divert_close": c_int,

        "divert_dump_packet": c_char_p,
    }

    def __init__(self, lib_path='', encoding='utf-8'):
        """
        Constructs a new driver instance
        :param lib_path: The OS path where to load the libdivert.dylib
        :param encoding: The character encoding to use (defaults to UTF-8)
        :return:
        """
        if not (lib_path and os.path.exists(lib_path) and os.path.isfile(lib_path)):
            lib_path = self._find_lib()
            if not lib_path:
                raise RuntimeError("Unable to find libdivert.dylib")

        self.dll_path = lib_path
        self.encoding = encoding
        self._load_lib(lib_path)

    def _find_lib(self):
        return ''

    def _load_lib(self, lib_path):
        """
        Loads the libdivert library, and configuring its arguments type
        :param lib_path: The OS path where to load the libdivert.dylib
        :return:
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

    def open_handle(self, port=0, filter_str="", flags=0):
        """
        Return a new handle already opened
        :param port: the port number to be diverted to, use 0 to auto select a unused port
        :param filter_str: the filter string
        :param flags: choose different mode
        :return: An opened Handle instance
        """
        return Handle(self, port, filter_str, flags, self.encoding).open()


class Handle:
    def __init__(self, libdivert=None, port=0, filter_str="", flags=0, encoding='utf-8'):
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
        self._filter = filter_str.encode(encoding)
        self._flags = flags
        self.encoding = encoding
        # create divert handle
        self._handle = self._lib.divert_create(self._port, self._flags, self._errmsg)

    @property
    def is_opened(self):
        return self._handle is not None

    def open(self):
        if self._lib.divert_activate(self._handle, self._errmsg) != 0:
            raise RuntimeError(self._errmsg.value)

        if self._filter:
            if self._lib.divert_set_filter(self._handle,
                                           self._filter,
                                           self._errmsg) != 0:
                raise RuntimeError(self._errmsg.value)

        self._lib.divert_loop(self._handle, -1)
        return self

    def read(self):
        status = self._lib.divert_read(self._handle,
                                       self._pktap_header,
                                       self._ip_packet,
                                       self._sockaddr)
        result = {
            'pktap': None,
            'packet': None,
            'sockaddr': None,
        }

        # try to extract the PKTAP header
        ptr_pktap = cast(self._pktap_header, POINTER(PktapHeader))
        if ptr_pktap[0].pth_comm > 0:
            result['pktap'] = deepcopy(ptr_pktap[0])

        # check if IP header is legal
        ptr_packet = cast(self._ip_packet, POINTER(IpHeader))
        header_len = ptr_packet[0].get_header_length()
        packet_length = ptr_packet[0].get_total_length()
        if packet_length > 0 and header_len > 0:
            result['packet'] = self._ip_packet[0:packet_length]

        # save the sockaddr for reinject
        result['sockaddr'] = self._sockaddr[0:Defaults.SOCKET_ADDR_SIZE]
        return result

    def reinject(self, ip_packet, sockaddr):
        pass

    def close(self):
        if self._handle:
            # first stop the event loop
            self._lib.divert_loop_stop(self._handle)

            # then close the divert handle
            if self._lib.divert_close(self._handle, self._errmsg) != 0:
                raise RuntimeError(self._errmsg.value)
