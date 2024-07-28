import base64
from hashlib import sha256
import hmac
import json
from typing import Annotated, Any, Dict, List, Union
from functools import singledispatch

from fastapi import Body, FastAPI, HTTPException, Response
from pydantic import BaseModel

from app.crypt import CryptBase64, InvalidException

app = FastAPI()

crypt = CryptBase64

hmac_key = "random_key".encode("utf-8")


@singledispatch
def _encrypt(payload) -> Any:
    return crypt.encrypt(str(payload).encode("utf-8"))


@_encrypt.register
def _(payload: list) -> Any:
    res = []
    for value in payload:
        res += crypt.encrypt(json.dumps(value).encode("utf-8"))
    return res


@_encrypt.register
def _(payload: dict) -> Any:
    res = {}
    for key, value in payload.items():
        res[key] = crypt.encrypt(json.dumps(value).encode("utf-8"))
    return res


@app.post("/encrypt")
def encrypt(payload: Any = Body(None)):
    print(type(payload))
    return _encrypt(payload)


@singledispatch
def _decrypt(payload) -> Any:
    try:
        print(payload)
        decrypted = crypt.decrypt(payload.encode("utf-8"))
        print(decrypted)
        return json.loads(decrypted)
    except (InvalidException, UnicodeDecodeError):
        return payload
    except json.JSONDecodeError:
        return decrypted


@_decrypt.register
def _(payload: list):
    res = []
    for value in payload:
        res += _decrypt(value)
    return res


@_decrypt.register
def _(payload: dict):
    res = {}
    for key, value in payload.items():
        res[key] = _decrypt(value)
    return res


@app.post("/decrypt")
def decrypt(payload: Any = Body(None)):
    print(type(payload))
    return _decrypt(payload)


def _sign(payload: bytes):
    return base64.b64encode(hmac.digest(key=hmac_key, msg=payload, digest=sha256))


@app.post("/sign")
def sign(payload: Any = Body(None)):
    print(payload)
    print(json.dumps(payload))
    res = _sign(json.dumps(payload).encode("utf-8"))
    return res


@app.post("/verify")
def verify(signature: Annotated[str, Body()], data: Annotated[Any, Body()]):
    print(any)
    msg = json.dumps(decrypt(data))
    digest = _sign(msg.encode("utf-8"))
    if hmac.compare_digest(digest, signature.encode("utf-8")):
        return
    raise HTTPException(status_code=400)
