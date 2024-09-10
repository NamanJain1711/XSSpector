# xssLog.py

from xsshelper import *

class Log:
    @classmethod
    def info(cls, text):
        print(f" [{GREEN}INFO{RESETEND}] {text}")

    @classmethod
    def warning(cls, text):
        print(f" [{YELLOW}WARNING{RESETEND}] {text}")

    @classmethod
    def high(cls, text):
        print(f" [{RED}CRITICAL{RESETEND}] {text}")
