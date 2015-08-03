from Crypto.Cipher import AES


def addr_to_str(addr):
    """Convert a Twisted IAddress object to readable string."""
    return addr.host + ":" + str(addr.port)


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
