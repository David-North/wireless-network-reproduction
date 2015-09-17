# encoding: utf8

from macdivert import MacDivert
from enum import Flags

__author__ = 'huangyan13@baidu.com'

lib_path = '/Users/baidu/Library/Caches/clion11/cmake/generated/b28c2630/b28c2630/Release/libdivert.dylib'

if __name__ == '__main__':
    libdivert = MacDivert(lib_path)
    fid = libdivert.open_handle(0, "", Flags.DIVERT_FLAG_BLOCK_IO | Flags.DIVERT_FLAG_WITH_PKTAP)
    for i in range(0, 5):
        fid.read()
    fid.close()
