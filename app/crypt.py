from abc import ABC, abstractmethod
import base64
import binascii
from typing import Any
from hashlib import sha256
import hmac


class InvalidException(Exception):
    pass


hmac_key = "random_key".encode("utf-8")


class Crypt(ABC):
    @classmethod
    @abstractmethod
    def encrypt(cls, value: bytes): ...

    @classmethod
    @abstractmethod
    def decrypt(cls, value: bytes): ...

    @classmethod
    def sign(cls, value: bytes):
        # Here base64 is only used to simplify handling of the signature and has
        # no link to the encryption algorithm.
        return base64.b64encode(hmac.digest(key=hmac_key, msg=value, digest=sha256))

    @classmethod
    def compare(cls, left: bytes, right: bytes):
        return hmac.compare_digest(left, right)


class CryptBase64(Crypt):
    @classmethod
    def encrypt(cls, value: bytes):
        return base64.b64encode(value)

    @classmethod
    def decrypt(cls, value: bytes):
        try:
            print(value)
            return base64.b64decode(value)
        except binascii.Error:
            raise InvalidException
