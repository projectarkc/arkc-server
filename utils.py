from Crypto.Cipher import AES
from time import time


def addr_to_str(addr):
    """Convert a Twisted IAddress object to readable string."""
    return addr.host + ":" + str(addr.port)


def get_timestamp():
    """Get the current time in milliseconds, in hexagon."""
    return hex(int(time() * 1000))[2:]


def parse_timestamp(timestamp):
    """Convert hexagon timestamp to integer (time in milliseconds)."""
    return int(timestamp, 16)


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
