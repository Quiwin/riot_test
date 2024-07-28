from fastapi.testclient import TestClient
import pytest
from app.main import app

client = TestClient(app)

inputs = [
    {},
    "{False}",
    "{1}",
    "{None}",
    "toto",
    {"msg": "Hello World"},
    {"foo": "foobar", "bar": {"isBar": True}},
]


@pytest.mark.parametrize("input", inputs)
def test_encrypt_decrypt(input):
    encrypt_response = client.post("/encrypt", json=input)

    assert encrypt_response.status_code == 200

    decrypt_response = client.post("/decrypt", json=encrypt_response.json())

    assert decrypt_response.status_code == 200

    assert decrypt_response.json() == input


def test_decrypt_invalid():
    input = {"key": "YWJjZA==", "val": "a"}
    decrypt_response = client.post("/decrypt", json=input)

    assert decrypt_response.status_code == 200

    assert decrypt_response.json() == {"key": "abcd", "val": "a"}


@pytest.mark.parametrize("input", inputs)
def test_sign_verify(input):
    sign_response = client.post("/sign", json=input)

    assert sign_response.status_code == 200

    verify_response = client.post(
        "/verify", json={"signature": sign_response.json(), "data": input}
    )

    assert verify_response.status_code == 200


@pytest.mark.parametrize("input", inputs)
def test_sign_verify_mismatch(input):
    verify_response = client.post(
        "/verify", json={"signature": "fuaifziaubf", "data": input}
    )

    assert verify_response.status_code == 400


@pytest.mark.parametrize("input", inputs)
def test_sign_encrypt_verify(input):
    sign_response = client.post("/sign", json=input)

    assert sign_response.status_code == 200

    encrypt_response = client.post("/encrypt", json=input)

    assert encrypt_response.status_code == 200

    verify_response = client.post(
        "/verify",
        json={"signature": sign_response.json(), "data": encrypt_response.json()},
    )

    assert verify_response.status_code == 200
