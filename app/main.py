import base64
import json
from typing import Annotated, Any
from functools import singledispatch

from fastapi import Body, FastAPI, HTTPException

from app.crypt import CryptBase64, InvalidException

app = FastAPI()

crypt = CryptBase64


def _internal_encrypt(value: Any):
    return crypt.encrypt(json.dumps(value).encode("utf-8"))


@singledispatch
def _encrypt(payload) -> Any:
    return _internal_encrypt(payload)


@_encrypt.register
def _(payload: list) -> Any:
    res = []
    for value in payload:
        res += _internal_encrypt(value)
    return res


@_encrypt.register
def _(payload: dict) -> Any:
    res = {}
    for key, value in payload.items():
        res[key] = _internal_encrypt(value)
    return res


@app.post("/encrypt")
def encrypt(payload: Any = Body(None)):
    return _encrypt(payload)


def internal_decrypt(payload):
    try:
        decrypted = crypt.decrypt(json.dumps(payload).encode("utf-8"))
        return json.loads(decrypted)
    except (InvalidException, UnicodeDecodeError):
        return payload
    except json.JSONDecodeError:
        return decrypted


@singledispatch
def _decrypt(payload) -> Any:
    return internal_decrypt(payload)


@_decrypt.register
def _(payload: list):
    res = []
    for value in payload:
        res += internal_decrypt(value)
    return res


@_decrypt.register
def _(payload: dict):
    res = {}
    for key, value in payload.items():
        res[key] = internal_decrypt(value)
    return res


@app.post("/decrypt")
def decrypt(payload: Any = Body(None)):
    return _decrypt(payload)


@app.post("/sign")
def sign(payload: Any = Body(None)):
    return CryptBase64.sign(json.dumps(payload).encode("utf-8"))


@app.post("/verify")
def verify(signature: Annotated[str, Body()], data: Annotated[Any, Body()]):
    msg = json.dumps(decrypt(data))
    digest = CryptBase64.sign(msg.encode("utf-8"))
    if CryptBase64.compare(digest, signature.encode("utf-8")):
        return
    raise HTTPException(status_code=400)
