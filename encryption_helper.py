import os

from blindal.crypter import Crypter


class PasswordDecrypter:
    @staticmethod
    def decrypt(password):
        keyfile = os.getenv('KEYFILE') or None
        if keyfile:
            f = open(keyfile, "r")
            try:
                key, iv = f.readline().split()
                return Crypter.decrypt(password, key, iv)
            finally:
                f.close()
        return password
