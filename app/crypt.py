from abc import ABC, abstractmethod
import base64
import binascii
from typing import Any


class InvalidException(Exception):
    pass


class Crypt(ABC):
    @classmethod
    @abstractmethod
    def encrypt(cls, value: bytes): ...

    @classmethod
    @abstractmethod
    def decrypt(cls, value: bytes): ...


# todo: bytes only?
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
