# encoding: utf8

import os
import time
import signal
import threading
import Tkinter as tk
from macdivert import MacDivert
from enum import Defaults
from tkMessageBox import showerror
from ctypes import POINTER, pointer, cast
from ctypes import (c_uint8, c_void_p, c_int32, c_char_p, c_int,  c_float,
                    create_string_buffer, c_size_t, c_ssize_t, c_uint64)

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
    def __init__(self, t, delay_time, size_filter_obj=None):
        super(DelayPipe, self).__init__()
        # first set function signature
        setattr(getattr(self._lib, 'delay_pipe_create'), "argtypes",
                [c_void_p, c_size_t, POINTER(c_float), POINTER(c_float), c_size_t])
        setattr(getattr(self._lib, 'delay_pipe_create'), "restype", c_void_p)
        arr_len = len(t)
        arr_type = c_float * arr_len
        # then check packet size filter handle
        filter_handle = None if size_filter_obj is None else size_filter_obj.handle
        self.handle = self._lib.delay_pipe_create(filter_handle, arr_len,
                                                  arr_type(*list(t)),
                                                  arr_type(*list(delay_time)),
                                                  Flags.DELAY_QUEUE_SIZE)


class Emulator(object):
    libdivert_ref = None

    emulator_argtypes = {
        'emulator_callback': [c_void_p, c_void_p, c_char_p, c_char_p],
        'emulator_create_config': [c_void_p, c_size_t],
        'emulator_destroy_config': [c_void_p],
        'emulator_start': [c_void_p],
        'emulator_stop': [c_void_p],
        'emulator_add_pipe': [c_void_p, c_void_p, c_int],
        'emulator_del_pipe': [c_void_p, c_void_p, c_int],
        'emulator_add_flag': [c_void_p, c_uint64],
        'emulator_clear_flags': [c_void_p],
        'emulator_clear_flag': [c_void_p, c_uint64],
        'emulator_set_dump_pcap': [c_void_p, c_char_p],
        'emulator_set_pid_list': [c_void_p, POINTER(c_int32), c_ssize_t],
        'emulator_config_check': [c_void_p, c_char_p],
        'emulator_is_running': [c_void_p],
    }

    emulator_restypes = {
        'emulator_callback': None,
        'emulator_create_config': c_void_p,
        'emulator_destroy_config': None,
        'emulator_start': None,
        'emulator_stop': None,
        'emulator_add_pipe': c_int,
        'emulator_del_pipe': c_int,
        'emulator_add_flag': None,
        'emulator_clear_flags': None,
        'emulator_clear_flag': None,
        'emulator_set_dump_pcap': None,
        'emulator_set_pid_list': None,
        'emulator_config_check': c_int,
        'emulator_is_running': c_int,
    }

    def __init__(self):
        # get reference for libdivert
        lib_obj = MacDivert()
        Emulator.libdivert_ref = lib_obj.get_reference()
        # initialize prototype of functions
        self._init_func_proto()
        # create divert handle and emulator config
        self.handle, self.config = self._create_config()
        # background thread for divert loop
        self.thread = None

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
        if lib.divert_set_signal_handler(signal.SIGINT,
                                         lib.divert_signal_handler_stop_loop,
                                         divert_handle) != 0:
            raise RuntimeError(divert_handle.errmsg)
        # activate divert handle
        if lib.divert_activate(divert_handle) != 0:
            raise RuntimeError(divert_handle.errmsg)
        return divert_handle, config

    def _divert_loop(self):
        lib = self.libdivert_ref
        lib.emulator_start(self.config)
        lib.divert_loop(self.handle, -1)

    def _divert_loop_stop(self):
        lib = self.libdivert_ref
        lib.divert_loop_stop(self.handle)
        lib.divert_wait_loop_finish(self.handle)
        lib.emulator_stop(self.config)

    def add_pipe(self, pipe, direction=Flags.DIRECTION_IN):
        lib = self.libdivert_ref
        if lib.emulator_add_pipe(self.config, pipe.handle, direction) != 0:
            raise RuntimeError("Pipe already exists.")

    def del_pipe(self, pipe, free_mem=False):
        lib = self.libdivert_ref
        if lib.emulator_del_pipe(self.config, pipe.handle, int(free_mem)) != 0:
            raise RuntimeError("Pipe do not exists.")

    def start(self, filter_str='ip from any to any via en0'):
        # first apply filter string
        lib = self.libdivert_ref
        if filter_str:
            if lib.divert_update_ipfw(self.handle, filter_str) != 0:
                raise RuntimeError(self.handle.errmsg)
        # then start a new thread to run emulator
        self.thread = threading.Thread(target=self._divert_loop)
        self.thread.start()

    def stop(self):
        self._divert_loop_stop()
        self.thread.join(timeout=1.0)
        if self.thread.isAlive():
            raise RuntimeError('Divert loop failed to stop.')


class BasicPipeWidget(object):
    pass


class DelayPipeWidget(object):
    pass


class EmulatorGUI(object):
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

    def __init__(self, master):
        self.master = master
        master.title("Network Emulator")
        master.protocol("WM_DELETE_WINDOW",
                        lambda: (master.quit(), master.destroy()))

        # first check root privilege
        if os.getuid() != 0:
            self.master.withdraw()
            showerror('Privilege Error', 'You should run this program as root.')
            self.master.destroy()
            return

        self.inbound_list = []
        self.outbound_list = []
        self.filter_str = tk.StringVar()
        self.data_file = tk.StringVar()

        self.init_filter()

        try:
            self.emulator = Emulator()
        except RuntimeError as e:
            self.master.withdraw()
            showerror('libdivert loading error', e.message)
            self.master.destroy()
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
            showerror('Emulator Starting Error', e.message)
            self.master.destroy()

    def init_filter(self):
        new_frame = tk.Frame(master=self.master)
        tk.Label(master=new_frame, text='Filter Expression').pack(side=tk.LEFT)
        tk.Entry(master=new_frame, textvariable=self.filter_str) \
            .pack(side=tk.LEFT, fill=tk.X, expand=True)
        new_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

    def load_conf(self):
        # do two things here:
        # 1. use raw API to set emulator configuration
        # 2. update all widgets
        pass

    def mainloop(self):
        self.master.mainloop()


if __name__ == '__main__':
    emulator = Emulator()
    emulator.add_pipe(DelayPipe([0, 5], [0.3, 0.6]))
    emulator.start()
    time.sleep(10)
    emulator.stop()
    print 'Program exited.'
