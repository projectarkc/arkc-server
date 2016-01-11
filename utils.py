from Crypto.Cipher import AES
from time import time
import random
import bisect


def addr_to_str(addr):
    """Convert a Twisted IAddress object to readable string."""
    return addr.host + ":" + str(addr.port)


def get_timestamp():
    """Get the current time in milliseconds, in hexagon."""
    return hex(int(time() * 1000)).rstrip("L").lstrip("0x")


def parse_timestamp(timestamp):
    """Convert hexagon timestamp to integer (time in milliseconds)."""
    return int(timestamp, 16)


def weighted_choice(l, f_weight):
    """Weighted random choice with the given weight function."""
    sum_weight = 0
    breakpoints = []
    for item in l:
        sum_weight += f_weight(item)
        breakpoints.append(sum_weight)
    r = random.random() * sum_weight
    i = bisect.bisect(breakpoints, r)
    return l[i]


class AESCipher:
    """A reusable wrapper of PyCrypto's AES cipher, i.e. resets every time."""

    def __init__(self, password, iv):
        self.password = password
        self.iv = iv
        self.reset()

    def reset(self):
        self.cipher = AES.new(self.password, AES.MODE_CFB, self.iv)

    def encrypt(self, data):
        enc = self.cipher.encrypt(data)
        self.reset()
        return enc

    def decrypt(self, data):
        dec = self.cipher.decrypt(data)
        self.reset()
        return dec
