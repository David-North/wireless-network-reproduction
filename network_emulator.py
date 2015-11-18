__author__ = 'huangyan13@baidu.com'

import os
from tkMessageBox import showerror

if __name__ == '__main__':
    showerror(message='uid=%d, euid=%d' % (os.getuid(), os.geteuid()))
