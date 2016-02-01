# encoding: utf8

import os
import libdivert as nids
from copy import deepcopy
from ctypes import cdll
from pwd import getpwuid
from enum import Defaults, Flags, Read_stats
from ctypes import POINTER, pointer, cast
from ctypes import (c_void_p, c_uint32, c_char_p, c_int,
                    create_string_buffer, c_ushort, c_ssize_t)
from models import ProcInfo, IpHeader, PacketHeader, DivertHandleRaw

__author__ = 'huangyan13@baidu.com'


class MacDivert:
    divert_argtypes = {
        # divert functions
        "divert_create": [c_int, c_uint32],
        "divert_activate": [POINTER(DivertHandleRaw)],
        "divert_update_ipfw": [POINTER(DivertHandleRaw), c_char_p],
        "divert_loop": [POINTER(DivertHandleRaw), c_int],
        "divert_is_looping": [POINTER(DivertHandleRaw)],
        "divert_loop_stop": [POINTER(DivertHandleRaw)],
        "divert_loop_join": [POINTER(DivertHandleRaw)],
        "divert_read": [POINTER(DivertHandleRaw), c_char_p, c_char_p, c_char_p],
        "divert_reinject": [POINTER(DivertHandleRaw), c_char_p, c_ssize_t, c_char_p],
        "divert_close": [POINTER(DivertHandleRaw)],
        "divert_is_inbound": [c_char_p, c_void_p],
        "divert_is_outbound": [c_char_p],
        "divert_set_callback": [c_void_p, c_void_p, c_void_p],
        "divert_set_signal_handler": [c_int, c_void_p, c_void_p],
        "divert_signal_handler_stop_loop": [c_int, c_void_p],
        "divert_init_pcap": [c_void_p],
        "divert_dump_pcap": [c_void_p, c_void_p],
        "divert_find_tcp_stream": [c_char_p],
        "divert_set_device": [c_void_p, c_char_p],

        # util functions
        "divert_load_kext": [c_char_p],
        "divert_unload_kext": [],
        "divert_dump_packet": [c_char_p, POINTER(PacketHeader), c_uint32, c_char_p],

        # note that we use char[] to store the ipfw rule for convenience
        # although the type is mismatched, the length of pointer variable is the same
        # so this would work
        "ipfw_compile_rule": [c_char_p, c_ushort, c_ushort, c_char_p, c_char_p],
        "ipfw_print_rule": [c_char_p],
        "ipfw_flush": [c_char_p],
    }

    divert_restypes = {
        "divert_create": POINTER(DivertHandleRaw),
        "divert_activate": c_int,
        "divert_update_ipfw": c_int,
        "divert_loop": c_int,
        "divert_is_looping": c_int,
        "divert_loop_stop": None,
        "divert_loop_join": None,
        "divert_read": c_ssize_t,
        "divert_reinject": c_ssize_t,
        "divert_close": c_int,
        "divert_is_inbound": c_int,
        "divert_is_outbound": c_int,
        "divert_set_callback": c_int,
        "divert_set_signal_handler": c_int,
        "divert_signal_handler_stop_loop": None,
        "divert_init_pcap": c_int,
        "divert_dump_pcap": c_int,
        "divert_find_tcp_stream": c_void_p,
        "divert_set_device": c_int,

        "divert_load_kext": c_int,
        "divert_unload_kext": c_int,
        "divert_dump_packet": c_char_p,
        "ipfw_compile_rule": c_int,
        "ipfw_print_rule": None,
        "ipfw_flush": c_int,
    }

    def __init__(self, lib_path='', kext_path='', encoding='utf-8'):
        """
        Constructs a new driver instance
        :param lib_path: The OS path where to load the libdivert.so
        :param lib_path: The OS path where to load the kernel extension
        :param encoding: The character encoding to use (defaults to UTF-8)
        :return:
        """
        if not (lib_path and os.path.exists(lib_path) and os.path.isfile(lib_path)):
            lib_path = self._find_lib()
            if not lib_path:
                raise RuntimeError("Unable to find libdivert.so")

        if not (kext_path and os.path.exists(kext_path) and os.path.isdir(kext_path)):
            kext_path = self._find_kext()
            if not kext_path:
                raise RuntimeError("Unable to find PacketPID.kext")

        self.dll_path = lib_path
        self.kext_path = kext_path
        self.encoding = encoding
        self._load_lib(lib_path)
        self._load_kext(kext_path)

    @staticmethod
    def _find_lib():
        module_path = os.sep.join(__file__.split(os.sep)[0:-1])
        return os.path.join(module_path, 'libdivert.so')

    @staticmethod
    def _find_kext():
        module_path = os.sep.join(__file__.split(os.sep)[0:-1])
        return os.path.join(module_path, 'PacketPID.kext')

    def _load_lib(self, lib_path):
        """
        Loads the libdivert library, and configuring its arguments type
        :param lib_path: The OS path where to load the libdivert.so
        :return: None
        """
        self._lib = cdll.LoadLibrary(lib_path)

        # set the types of parameters
        for func_name, argtypes in self.divert_argtypes.items():
            # first check if function exists
            if not hasattr(self._lib, func_name):
                raise RuntimeError("Not a valid libdivert library")
            setattr(getattr(self._lib, func_name), "argtypes", argtypes)

        # set the types of return value
        for func_name, restype in self.divert_restypes.items():
            setattr(getattr(self._lib, func_name), "restype", restype)

    @staticmethod
    def chown_recursive(path, uid, gid):
        os.chown(path, uid, gid)
        for root, dirs, files in os.walk(path):
            for item in dirs:
                os.chown(os.path.join(root, item), uid, gid)
            for item in files:
                os.chown(os.path.join(root, item), uid, gid)

    def _load_kext(self, kext_path):
        uid, gid = os.stat(kext_path).st_uid, os.stat(kext_path).st_gid
        self.chown_recursive(kext_path, 0, 0)
        ret_val = self._lib.divert_load_kext(kext_path)
        self.chown_recursive(kext_path, uid, gid)
        if ret_val != 0:
            raise OSError("Could not load kernel extension for libdivert")

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
        :return: An opened DivertHandle instance
        """
        return DivertHandle(self, port, filter_str, flags, count, self.encoding).open()


class DivertHandle:
    def __init__(self, libdivert=None, port=0, filter_str="",
                 flags=0, count=-1, encoding='utf-8'):
        if not libdivert:
            # Try to construct by loading from the library path
            self._libdivert = MacDivert()
        else:
            self._libdivert = libdivert
        # buffer to store packet data
        self._ip_packet = create_string_buffer(Defaults.PACKET_BUFFER_SIZE)
        # buffer to store process information
        self._proc_info_buffer = create_string_buffer(Defaults.PROC_INFO_SIZE)
        # buffer to store socket address
        self._sockaddr = create_string_buffer(Defaults.SOCKET_ADDR_SIZE)

        self._lib = self._libdivert.get_reference()
        self._port = port
        self._count = count
        self._filter = filter_str.encode(encoding)
        self._flags = flags
        self.encoding = encoding
        # create divert handle
        self._handle = self._lib.divert_create(self._port,
                                               self._flags |
                                               Flags.DIVERT_FLAG_BLOCK_IO |
                                               Flags.DIVERT_FLAG_FAST_EXIT)
        self._cleaned = True
        # create active flag
        self.active = False

    def __del__(self):
        if not self._cleaned:
            self._cleaned = True
            # free close the divert handle
            if self._lib.divert_close(self._handle) != 0:
                raise RuntimeError(self._handle[0].errmsg)

    def ipfw_compile_rule(self, rule_str, port):
        errmsg = create_string_buffer(Defaults.DIVERT_ERRBUF_SIZE)
        rule_data = create_string_buffer(Defaults.IPFW_RULE_SIZE)
        if self._lib.ipfw_compile_rule(rule_data, port, rule_str, errmsg) != 0:
            raise RuntimeError("Error rule: %s" % errmsg.value)
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
        if self._lib.divert_activate(self._handle) != 0:
            raise RuntimeError(self._handle[0].errmsg)
        self.active = True
        self._cleaned = False

        if self._filter:
            self.set_filter(self._filter)

        self._lib.divert_loop(self._handle, self._count)

        return self

    def open_pcap(self, filename):
        return PcapHandle(filename, self._libdivert)

    def close(self):
        if self.active:
            # stop the event loop
            self._lib.divert_loop_stop(self._handle)
            self.active = False

    def set_filter(self, filter_str):
        if filter_str:
            if self._lib.divert_update_ipfw(self._handle,
                                            filter_str) != 0:
                raise RuntimeError("Error rule: %s" %
                                   self._handle[0].errmsg)
            else:
                return True
        else:
            return False

    def read(self):
        status = self._lib.divert_read(self._handle,
                                       self._proc_info_buffer,
                                       self._ip_packet,
                                       self._sockaddr)
        ret_val = Packet()
        if status == 0:
            # try to extract the process information
            ptr_proc_info = cast(self._proc_info_buffer, POINTER(ProcInfo))
            if ptr_proc_info[0].pid != -1 or ptr_proc_info[0].epid != -1:
                ret_val.proc = deepcopy(ptr_proc_info[0])

            # check if IP header is legal
            ptr_packet = cast(self._ip_packet, POINTER(IpHeader))
            header_len = ptr_packet[0].get_header_length()
            packet_length = ptr_packet[0].get_total_length()
            if packet_length > 0 and header_len > 0:
                ret_val.ip_data = self._ip_packet[0:packet_length]

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

        if not packet_obj or not packet_obj.sockaddr or not packet_obj.ip_data:
            raise RuntimeError("Invalid packet data.")

        return self._lib.divert_reinject(self._handle, packet_obj.ip_data,
                                         -1, packet_obj.sockaddr)

    def is_inbound(self, sockaddr):
        return self._lib.divert_is_inbound(sockaddr, None) != 0

    def is_outbound(self, sockaddr):
        return self._lib.divert_is_outbound(sockaddr) != 0

    def set_stop_signal(self, signum):
        return self._lib.divert_set_signal_handler(
            signum, self._lib.divert_signal_handler_stop_loop, self._handle
        )

    def find_tcp_stream(self, packet):
        if self.eof:
            raise RuntimeError("Divert socket is closed.")
        stream_p = self._lib.divert_find_tcp_stream(packet.ip_data)
        if stream_p:
            return nids.convert(c_void_p(stream_p))

    # Context Manager protocol
    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()


class PcapHandle:
    libc_argtypes = {
        "fopen": [c_char_p, c_char_p],
        "fclose": [c_void_p],
    }

    libc_restypes = {
        'fopen': c_void_p,
        'fclose': c_int,
    }

    def __init__(self, filename=None, libdivert=None):
        self.filename = filename
        self._load_libc()
        self._lib = libdivert.get_reference()
        self._errmsg = create_string_buffer(Defaults.PACKET_BUFFER_SIZE)

        self._fp = self._libc.fopen(filename, 'wb')
        if not self._fp:
            raise RuntimeError("Couldn't create file %s" % self.filename)

        if self._lib.divert_init_pcap(self._fp, self._errmsg) != 0:
            raise RuntimeError("Couldn't init file %s: %s" %
                               (self.filename, self._errmsg.value))

    def __del__(self):
        if self._fp:
            self.close()

    def _load_libc(self):
        self._libc = cdll.LoadLibrary('libc.dylib')
        # set the types of parameters
        for func_name, argtypes in self.libc_argtypes.items():
            if not hasattr(self._libc, func_name):
                raise RuntimeError("Not a valid libC library")
            setattr(getattr(self._libc, func_name), "argtypes", argtypes)
        # set the types of return value
        for func_name, restype in self.libc_restypes.items():
            setattr(getattr(self._libc, func_name), "restype", restype)

    def write(self, packet):
        if self._lib.divert_dump_pcap(packet.ip_data,
                                      self._fp, self._errmsg) != 0:
            raise RuntimeError("Couldn't write into %s: %s" %
                               (self.filename, self._errmsg.value))

    def close(self):
        if self._fp:
            if self._libc.fclose(self._fp) == 0:
                self._fp = None
            else:
                raise RuntimeError("File %s could not be closed!" % self.filename)
        else:
            raise RuntimeError("File %s is not opened!" % self.filename)


class Packet:
    def __init__(self):
        self.proc = None
        self.ip_data = None
        self.sockaddr = None
        self.valid = False
        self.flag = 0

    def __setitem__(self, key, value):
        if key == 'proc':
            self.proc = value
        elif key == 'ip_data':
            self.ip_data = value
        elif key == 'sockaddr':
            self.sockaddr = value
        elif key == 'flag':
            self.flag = value
        else:
            raise KeyError("No suck key: %s" % key)

    def __getitem__(self, item):
        if item == 'proc':
            return self.proc
        elif item == 'ip_data':
            return self.ip_data
        elif item == 'sockaddr':
            return self.sockaddr
        elif item == 'flag':
            return self.flag
        else:
            return None
