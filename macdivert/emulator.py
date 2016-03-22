# encoding: utf8

import os
import sys
import json
import copy
import psutil
import threading
import netifaces
import socket
import time
import signal
import Tkinter as tk
from macdivert import MacDivert
from tkMessageBox import showerror, showwarning
from enum import Defaults
from tkFileDialog import askopenfilename, askdirectory
from ctypes import POINTER, pointer, cast
from ctypes import (c_uint8, c_void_p, c_int32, c_char_p, c_int,  c_float,
                    create_string_buffer, c_size_t, c_ssize_t, c_uint64)

# import pydevd
# pydevd.settrace('localhost', port=9999, stdoutToServer=True, stderrToServer=True)

__author__ = 'huangyan13@baidu.com'


class Flags(object):
    # direction flags
    DIRECTION_IN = 0
    DIRECTION_OUT = 1
    DIRECTION_UNKNOWN = 2

    # feature flags
    EMULATOR_IS_RUNNING = 1
    EMULATOR_DUMP_PCAP = (1 << 1)
    EMULATOR_RECHECKSUM = (1 << 2)

    # pipe flags
    PIPE_DROP = 0
    PIPE_DELAY = 1
    PIPE_THROTTLE = 2
    PIPE_DISORDER = 3
    PIPE_BITERR = 4
    PIPE_DUPLICATE = 5
    PIPE_BANDWIDTH = 6
    PIPE_REINJECT = 7

    # buffer size
    EMULALTOR_BUF_SIZE = 8172
    DELAY_QUEUE_SIZE = 8172


class BasicPipe(object):
    def __init__(self):
        self.handle = None
        if Emulator.libdivert_ref is None:
            raise RuntimeError("Should first instantiate an Emulator object")
        else:
            self._lib = Emulator.libdivert_ref


class DelayPipe(BasicPipe):
    def __init__(self, delay_time, t=None,
                 queue_size=Flags.DELAY_QUEUE_SIZE,
                 size_filter_obj=None):
        super(DelayPipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'delay_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float), c_size_t])
        setattr(getattr(self._lib, 'delay_pipe_create'), "restype", c_void_p)
        arr_len = len(delay_time)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.delay_pipe_create(filter_handle, arr_len,
                                                  arr_type(*list(t)) if t else None,
                                                  arr_type(*list(delay_time)),
                                                  queue_size)


class DropPipe(BasicPipe):
    def __init__(self, drop_rate, t=None,
                 size_filter_obj=None):
        super(DropPipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'drop_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float)])
        setattr(getattr(self._lib, 'drop_pipe_create'), "restype", c_void_p)
        arr_len = len(drop_rate)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.drop_pipe_create(filter_handle, arr_len,
                                                 arr_type(*list(t)) if t else None,
                                                 arr_type(*list(drop_rate)))


class BandwidthPipe(BasicPipe):
    def __init__(self, t, bandwidth, queue_size=Flags.DELAY_QUEUE_SIZE, size_filter_obj=None):
        super(BandwidthPipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'bandwidth_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float), c_size_t])
        setattr(getattr(self._lib, 'bandwidth_pipe_create'), "restype", c_void_p)
        arr_len = len(t)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.bandwidth_pipe_create(filter_handle, arr_len,
                                                      arr_type(*list(t)),
                                                      arr_type(*list(bandwidth)),
                                                      queue_size)


class BiterrPipe(BasicPipe):
    def __init__(self, t, biterr_rate, max_flip, size_filter_obj=None):
        super(BiterrPipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'biterr_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float), c_int])
        setattr(getattr(self._lib, 'biterr_pipe_create'), "restype", c_void_p)
        arr_len = len(t)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.biterr_pipe_create(filter_handle, arr_len,
                                                   arr_type(*list(t)),
                                                   arr_type(*list(biterr_rate)), max_flip)


class DisorderPipe(BasicPipe):
    def __init__(self, t, disorder_rate, queue_size, max_disorder, size_filter_obj=None):
        super(DisorderPipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'disorder_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float), c_size_t, c_int])
        setattr(getattr(self._lib, 'disorder_pipe_create'), "restype", c_void_p)
        arr_len = len(t)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.disorder_pipe_create(filter_handle, arr_len,
                                                     arr_type(*list(t)),
                                                     arr_type(*list(disorder_rate)),
                                                     queue_size, max_disorder)


class DuplicatePipe(BasicPipe):
    def __init__(self, t, duplicate_rate, max_duplicate, size_filter_obj=None):
        super(DuplicatePipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'duplicate_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float), c_size_t])
        setattr(getattr(self._lib, 'duplicate_pipe_create'), "restype", c_void_p)
        arr_len = len(t)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.duplicate_pipe_create(filter_handle, arr_len,
                                                      arr_type(*list(t)),
                                                      arr_type(*list(duplicate_rate)),
                                                      max_duplicate)


class ThrottlePipe(BasicPipe):
    def __init__(self, t_start, t_end, queue_size, size_filter_obj=None):
        super(ThrottlePipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'throttle_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float), c_size_t])
        setattr(getattr(self._lib, 'throttle_pipe_create'), "restype", c_void_p)
        arr_len = len(t_start)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.throttle_pipe_create(filter_handle, arr_len,
                                                     arr_type(*list(t_start)),
                                                     arr_type(*list(t_end)),
                                                     queue_size)


class Emulator(object):
    libdivert_ref = None

    emulator_argtypes = {
        'emulator_callback': [c_void_p, c_void_p, c_char_p, c_char_p],
        'emulator_create_config': [c_void_p],
        'emulator_destroy_config': [c_void_p],
        'emulator_flush': [c_void_p],
        'emulator_add_pipe': [c_void_p, c_void_p, c_int],
        'emulator_del_pipe': [c_void_p, c_void_p, c_int],
        'emulator_add_flag': [c_void_p, c_uint64],
        'emulator_clear_flags': [c_void_p],
        'emulator_clear_flag': [c_void_p, c_uint64],
        'emulator_set_dump_pcap': [c_void_p, c_char_p],
        'emulator_set_pid_list': [c_void_p, POINTER(c_int32), c_ssize_t],
        'emulator_config_check': [c_void_p, c_char_p],
        'emulator_is_running': [c_void_p],
        'emulator_data_size': [c_void_p, c_int],
        'emulator_create_size_filter': [c_size_t, POINTER(c_size_t), POINTER(c_float)],
    }

    emulator_restypes = {
        'emulator_callback': None,
        'emulator_create_config': c_void_p,
        'emulator_destroy_config': None,
        'emulator_flush': None,
        'emulator_add_pipe': c_int,
        'emulator_del_pipe': c_int,
        'emulator_add_flag': None,
        'emulator_clear_flags': None,
        'emulator_clear_flag': None,
        'emulator_set_dump_pcap': None,
        'emulator_set_pid_list': None,
        'emulator_config_check': c_int,
        'emulator_is_running': c_int,
        'emulator_data_size': c_uint64,
        'emulator_create_size_filter': c_void_p,
    }

    class PacketSizeFilter(object):
        def __init__(self, size_arr, rate_arr):
            if len(size_arr) != len(rate_arr):
                raise RuntimeError('Invalid packet size filter')
            arr_len = len(size_arr)
            lib = Emulator.libdivert_ref
            self.handle = lib.emulator_create_size_filter(len(size_arr),
                                                          (c_size_t * arr_len)(*size_arr),
                                                          (c_float * arr_len)(*rate_arr))

    def __init__(self):
        # get reference for libdivert
        if Emulator.libdivert_ref is None:
            lib_obj = MacDivert()
            Emulator.libdivert_ref = lib_obj.get_reference()
            # initialize prototype of functions
            self._init_func_proto()
        # create divert handle and emulator config
        self.handle, self.config = self._create_config()
        # background thread for divert loop
        self.thread = None
        # list to store pids
        self.pid_list = []
        # error information
        self.errmsg = create_string_buffer(Defaults.DIVERT_ERRBUF_SIZE)
        self.quit_loop = False
        self.is_waiting = False

    def __del__(self):
        lib = self.libdivert_ref
        lib.emulator_destroy_config(self.config)
        if lib.divert_close(self.handle) != 0:
            raise RuntimeError('Divert handle could not be cleaned.')

    def _init_func_proto(self):
        # set the types of parameters
        for func_name, argtypes in self.emulator_argtypes.items():
            # first check if function exists
            if not hasattr(self.libdivert_ref, func_name):
                raise RuntimeError("Not a valid libdivert library")
            setattr(getattr(self.libdivert_ref, func_name), "argtypes", argtypes)

        # set the types of return value
        for func_name, restype in self.emulator_restypes.items():
            setattr(getattr(self.libdivert_ref, func_name), "restype", restype)

    def _create_config(self):
        lib = self.libdivert_ref
        # create divert handle
        divert_handle = lib.divert_create(0, 0)
        if not divert_handle:
            raise RuntimeError('Fail to create divert handle.')
        # create config handle
        config = lib.emulator_create_config(divert_handle,
                                            Flags.EMULALTOR_BUF_SIZE)
        if not config:
            raise RuntimeError('Fail to create emulator configuration')
        # set callback function and callback data for divert handle
        if lib.divert_set_callback(divert_handle,
                                   lib.emulator_callback,
                                   config) != 0:
            raise RuntimeError(divert_handle.errmsg)
        # activate divert handle
        if lib.divert_activate(divert_handle) != 0:
            raise RuntimeError(divert_handle.errmsg)
        return divert_handle, config

    def _divert_loop(self, filter_str):
        # first add all PIDs into list
        self._wait_pid()
        if self.quit_loop:
            self.quit_loop = False
            return
        lib = self.libdivert_ref
        lib.divert_loop(self.handle, -1)

    def _divert_loop_stop(self):
        lib = self.libdivert_ref
        lib.divert_loop_stop(self.handle)
        lib.divert_loop_wait(self.handle)
        print 'Emulator stop OK'
        lib.emulator_flush(self.config)
        print 'Emulator flush OK'

    def add_pipe(self, pipe, direction=Flags.DIRECTION_IN):
        lib = self.libdivert_ref
        if lib.emulator_add_pipe(self.config, pipe.handle, direction) != 0:
            raise RuntimeError("Pipe already exists.")

    def del_pipe(self, pipe, free_mem=False):
        lib = self.libdivert_ref
        if lib.emulator_del_pipe(self.config, pipe.handle, int(free_mem)) != 0:
            raise RuntimeError("Pipe do not exists.")

    def add_pid(self, pid):
        self.pid_list.append(pid)

    def set_device(self, dev_name):
        lib = self.libdivert_ref
        if lib.divert_set_device(self.handle, dev_name) != 0:
            raise RuntimeError('Could not set capture device.')

    def _wait_pid(self):
        # first wait until all processes are started
        proc_list = filter(lambda x: isinstance(x, str) or isinstance(x, unicode), self.pid_list)
        real_pid_list = filter(lambda x: isinstance(x, int), self.pid_list)
        self.is_waiting = True
        while not self.quit_loop:
            if len(real_pid_list) == len(self.pid_list):
                break
            for proc in psutil.process_iter():
                proc_name = proc.name().lower()
                for name in proc_list:
                    if name.lower() in proc_name:
                        real_pid_list.append(proc.pid)
            print 'Waiting for process: %s' % ', '.join(proc_list)
            time.sleep(0.2)
        self.is_waiting = False
        if self.quit_loop:
            return
        print 'Found PID: %s' % ', '.join(map(str, real_pid_list))
        lib = self.libdivert_ref
        arr_len = len(real_pid_list)
        arr_type = c_int32 * arr_len
        lib.emulator_set_pid_list(self.config, arr_type(*real_pid_list), arr_len)

    def set_dump(self, directory):
        lib = self.libdivert_ref
        if not os.path.isdir:
            raise RuntimeError('Invalid save position.')
        lib.emulator_set_dump_pcap(self.config, directory)

    def start(self, filter_str=''):
        # first check the config
        lib = self.libdivert_ref
        if lib.emulator_config_check(self.config, self.errmsg) != 0:
            raise RuntimeError('Invalid configuration:\n%s' % self.errmsg.value)
        print 'Config check OK'
        # then apply filter string
        if filter_str:
            if lib.divert_update_ipfw(self.handle, filter_str) != 0:
                raise RuntimeError(self.handle.errmsg)
        # start a new thread to run emulator
        self.thread = threading.Thread(target=self._divert_loop, args=(filter_str,))
        self.thread.start()

    def stop(self):
        # if emulator is waiting on PIDs
        # then just use a quit loop flag
        if self.is_waiting:
            self.quit_loop = True
        else:
            self._divert_loop_stop()
        self.thread.join(timeout=1.0)
        if self.thread.isAlive():
            raise RuntimeError('Divert loop failed to stop.')
        self.thread = None

    @property
    def is_looping(self):
        return self.thread is not None and self.thread.isAlive()

    def data_size(self, direction):
        lib = self.libdivert_ref
        return lib.emulator_data_size(self.config, direction)


class EmulatorGUI(object):
    LOCAL_MODE = 0
    ROUTER_MODE = 1
    prompt_str = 'PID / comma separated process name'

    default_device = 'bridge100'

    kext_errmsg = """
    Kernel extension load failed.
    Please check if you have root privilege on your Mac.
    Since we do not have a valid developer certificate,
    you should manually disable the kernel extension protection.

    For Mac OS X 10.11:
    1. Start your computer from recovery mode: restart your Mac
    and hold down the Command and R keys at startup.
    2. Run "csrutil enable --without kext" under recovery mode.
    3. Reboot.

    For Mac OS X 10.10:
    1. Run "sudo nvram boot-args=kext-dev-mode=1" from terminal.
    2. Reboot.
    """

    pipe_name2type = {
        'drop': DropPipe,
        'delay': DelayPipe,
        'biterr': BiterrPipe,
        'disorder': DisorderPipe,
        'throttle': ThrottlePipe,
        'duplicate': DuplicatePipe,
        'bandwidth': BandwidthPipe,
    }

    def exit_func(self):
        if self.emulator is not None:
            try:
                self.emulator.stop()
                self.emulator = None
            except Exception as e:
                print e.message
        self._flush_ipfw()
        self.master.quit()
        self.master.destroy()

    def _flush_ipfw(self):
        if Emulator.libdivert_ref is not None:
            buf = create_string_buffer(256)
            lib = Emulator.libdivert_ref
            lib.ipfw_flush(buf)

    def decide_iface(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("gmail.com", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            showwarning('Network Error',
                        ('Your host machine may not have a valid network connection.\n'
                         'You should **manually** choose your network device name in filter rule.'))
            return
        iface_lst = netifaces.interfaces()
        for iface in iface_lst:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                addr_dict = addrs[netifaces.AF_INET][0]
                if 'addr' in addr_dict:
                    if addr_dict['addr'] == local_ip:
                        print 'Found activate network interface: %s' % iface
                        self.iface = iface
                        return

    def __init__(self, master):
        self.master = master
        self.emulator = None

        self.conf_dict = {}
        self.conf_name = tk.StringVar()
        self.conf_frame = None

        master.title("Wireless Network Reproduction")
        master.protocol("WM_DELETE_WINDOW", self.exit_func)

        # first check root privilege
        if os.getuid() != 0:
            self.master.withdraw()
            showerror('Privilege Error', 'You should run this program as root.')
            self.master.destroy()
            return

        # then find the current activate network interface
        self.iface = '<network device name>'
        self.decide_iface()
        self.default_rule = 'ip from any to any via %s' % self.iface

        self.inbound_list = []
        self.outbound_list = []
        self.filter_str = tk.StringVar(value=self.default_rule)
        self.proc_str = tk.StringVar(value=self.prompt_str)
        self.dev_str = tk.StringVar()
        self.dump_pos = tk.StringVar()
        self.divert_unknown = tk.IntVar(value=1)

        self.start_btn = None
        self.filter_entry = None
        self.proc_entry = None
        self.dev_entry = None
        self.mode = tk.IntVar(self.LOCAL_MODE)
        self.init_GUI()

        try:
            Emulator()
        except OSError:
            def close_func():
                self.master.quit()
                self.master.destroy()
            self.master.withdraw()
            top = tk.Toplevel(self.master)
            top.title('Kernel Extension Error')
            tk.Message(top, text=self.kext_errmsg)\
                .pack(side=tk.TOP, fill=tk.BOTH, expand=True)
            tk.Button(top, text="Close", command=close_func).pack(side=tk.TOP)
            top.protocol("WM_DELETE_WINDOW", close_func)
        except Exception as e:
            self.master.withdraw()
            showerror('Emulator Loading Error', e.message)
            self.master.destroy()

    def init_GUI(self):
        new_frame = tk.Frame(master=self.master)
        tk.Button(master=new_frame, text='Add Configuration',
                  command=self.load_data_file).pack(side=tk.LEFT)
        self.conf_frame = tk.Frame(master=new_frame)
        self.conf_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        new_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        new_frame = tk.Frame(master=self.master)
        tk.Label(master=new_frame, text='Dump .pcap to').pack(side=tk.LEFT)
        tk.Entry(master=new_frame, textvariable=self.dump_pos)\
            .pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Button(master=new_frame, text='Select',
                  command=self.load_dump_pos).pack(side=tk.LEFT)
        new_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        new_frame = tk.Frame(master=self.master)
        tk.Label(master=new_frame, text='Filter Rule').pack(side=tk.LEFT)
        self.filter_entry = tk.Entry(master=new_frame, textvariable=self.filter_str, font='Monaco')
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        new_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        new_frame = tk.Frame(master=self.master)
        tk.Label(master=new_frame, text='Process List').pack(side=tk.LEFT)
        self.proc_entry = tk.Entry(master=new_frame, textvariable=self.proc_str,
                                   font='Monaco', width=len(self.proc_str.get()))
        self.proc_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(master=new_frame, text='unknown').pack(side=tk.LEFT)
        tk.Checkbutton(master=new_frame, variable=self.divert_unknown).pack(side=tk.LEFT)
        new_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        new_frame = tk.Frame(master=self.master)
        tk.Label(master=new_frame, text='Mode').pack(side=tk.LEFT)
        tk.Radiobutton(master=new_frame, text="Local", variable=self.mode,
                       value=0, command=self._switch_mode).pack(side=tk.LEFT)
        tk.Radiobutton(master=new_frame, text="WiFi", variable=self.mode,
                       value=1, command=self._switch_mode).pack(side=tk.LEFT)
        self.dev_entry = tk.Entry(master=new_frame, textvariable=self.dev_str,
                                  state=tk.DISABLED, font='Monaco', width=12)
        self.dev_entry.pack(side=tk.LEFT)
        tk.Button(master=new_frame, text='Fix network',
                  command=self._flush_ipfw).pack(side=tk.LEFT)
        new_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        new_frame = tk.Frame(master=self.master)
        self.start_btn = tk.Button(master=new_frame, text='Start',
                                   command=self.start, font=('Monaco', 20))
        self.start_btn.pack(side=tk.TOP)
        new_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

    def _switch_mode(self):
        if self.mode.get() == self.LOCAL_MODE:
            # local mode
            self.dev_str.set('')
            self.dev_entry.config(state=tk.DISABLED)
            self.filter_entry.config(state=tk.NORMAL)
            self.proc_entry.config(state=tk.NORMAL)
            self.filter_str.set(self.default_rule)
            self.proc_str.set(self.prompt_str)
        elif self.mode.get() == self.ROUTER_MODE:
            self.dev_entry.config(state=tk.NORMAL)
            self.dev_str.set(self.default_device)
            self.filter_str.set('ip from any to any')
            self.proc_str.set('')
            self.filter_entry.config(state=tk.DISABLED)
            self.proc_entry.config(state=tk.DISABLED)
        else:
            raise RuntimeError('Unknown Mode!')

    def load_data_file(self):
        dir_name, file_name = os.path.split(__file__)
        dir_name = os.path.join(dir_name, 'examples')
        file_path = askopenfilename(title='Choose .json file', initialdir=dir_name)
        if file_path and os.path.isfile(file_path):
            try:
                head, tail = os.path.split(file_path)
                with open(file_path, 'r') as fid:
                    data = fid.read()
                    self.conf_dict[file_path] = json.loads(data)
                    tk.Radiobutton(self.conf_frame, text=tail.split('.')[0],
                                   variable=self.conf_name,
                                   value=file_path).pack(side=tk.LEFT)
                    self.conf_name.set(file_path)
            except Exception as e:
                showerror(title='Open file',
                          message='Unable to load json: %s' % e.message)

    def load_dump_pos(self):
        dir_name, file_name = os.path.split(__file__)
        dir_name = os.path.join(dir_name, 'examples')
        dir_path = askdirectory(title='Choose dump position',
                                initialdir=dir_name)
        self.dump_pos.set(dir_path)

    def start(self):
        if self.conf_name.get() not in self.conf_dict:
            showerror(title='Configuration Error',
                      message='No available conf file.')
            return
        if self.proc_str.get() == self.prompt_str:
            showerror(title='Process/PID Error',
                      message='You should set legal PIDs or leave it blank.')
            return
        if self.emulator is None:
            try:
                self.emulator = Emulator()
                self._load_config()
                self.emulator.start(self.filter_str.get())
                self.start_btn.config(text='Stop')
            except Exception as e:
                self.emulator = None
                showerror(title='Runtime error',
                          message='Unable to start emulator:\n%s' % e.message)
        else:
            try:
                self.emulator.stop()
                self.emulator = None
                self.start_btn.config(text='Start')
            except Exception as e:
                self.emulator = None
                showerror(title='Runtime error',
                          message='Unable to stop emulator:\n%s' % e.message)

    def _load_config(self):
        if self.emulator is None:
            return
        # set dump position
        dump_path = self.dump_pos.get()
        if dump_path and os.path.isdir(dump_path):
            self.emulator.set_dump(dump_path)
        # set emulation device
        dev_name = self.dev_str.get()
        if dev_name:
            self.emulator.set_device(dev_name)
        # set pid list if not empty
        if self.mode.get() == self.LOCAL_MODE:
            pid_str = self.proc_str.get().strip()
            if pid_str and pid_str != self.prompt_str:
                if self.divert_unknown.get():
                    self.emulator.add_pid(-1)
                for pid in map(lambda x: x.strip(), pid_str.split(',')):
                    try:
                        pid_int = int(pid)
                        self.emulator.add_pid(pid_int)
                    except:
                        self.emulator.add_pid(pid)
        elif self.mode.get() == self.ROUTER_MODE:
            # this is a fake PID, nothing would match
            self.emulator.add_pid(-2)
        else:
            raise RuntimeError("Unknown Mode!")
        # finally load all pipes
        for pipe in copy.deepcopy(self.conf_dict[self.conf_name.get()]):
            if not isinstance(pipe, dict):
                raise TypeError('Invalid configuration')
            pipe_name = pipe.pop('pipe', None)
            if not pipe_name:
                raise RuntimeError('Configuration do not have pipe type')
            direction = pipe.pop('direction', None)
            if not direction:
                raise RuntimeError('Configuration do not have direction field')
            if direction == "out":
                dir_flag = Flags.DIRECTION_OUT
            elif direction == "in":
                dir_flag = Flags.DIRECTION_IN
            else:
                raise RuntimeError('Unknown direction flag')
            size_filter = self._create_filter(pipe.pop('filter', None))
            try:
                pipe_type = self.pipe_name2type[pipe_name.lower()]
            except:
                raise RuntimeError('Invalid pipe type')
            pipe_obj = pipe_type(size_filter_obj=size_filter, **pipe)
            self.emulator.add_pipe(pipe_obj, dir_flag)

    def _create_filter(self, filter_dict):
        if not filter_dict:
            return None
        size_arr = filter_dict.get('size')
        rate_arr = filter_dict.get('rate')
        if not size_arr or not rate_arr:
            return None
        return Emulator.PacketSizeFilter(size_arr, rate_arr)

    def mainloop(self):
        self.master.mainloop()


if __name__ == '__main__':

    pid_num = 0

    try:
        pid_num = int(sys.argv[1])
    except Exception as e:
        print 'Exception: %s' % e.message
        print 'Usage: python emulator.py <PID>'
        exit(-1)

    emulator = Emulator()
    emulator.add_pid(pid_num)
    emulator.add_pid(-1)
    emulator.set_dump('/Users/baidu/Downloads')

    emulator.add_pipe(DelayPipe([0, 10], [0.1, 0.6], 1024), Flags.DIRECTION_IN)

    is_looping = True

    # register signal handler
    def sig_handler(signum, frame):
        print 'Catch signal: %d' % signum
        global is_looping
        is_looping = False
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTSTP, sig_handler)

    perMB = 1024 * 1024

    trans_size = 0
    # start loop
    emulator.start('ip from any to any via en0')
    while is_looping:
        data_size = emulator.data_size(Flags.DIRECTION_IN)
        if data_size > 5 * perMB:
            print 'Finish'
            break
        if data_size > (trans_size + 1) * perMB:
            trans_size = data_size / perMB
            print 'Transfer %d MB data.' % trans_size
        time.sleep(0.5)
    # stop loop
    emulator.stop()
    print 'Program exited.'
