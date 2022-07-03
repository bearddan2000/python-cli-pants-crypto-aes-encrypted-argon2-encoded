#!/usr/bin/env python

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AESCipher:
    def __init__(self):
        self.bs = 16
        key = os.urandom(self.bs*2)
        iv = os.urandom(self.bs)
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    def encrypt(self, raw):
        raw = self._pad(raw)
        encryptor = self.cipher.encryptor()
        return encryptor.update(raw.encode()) + encryptor.finalize()

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
