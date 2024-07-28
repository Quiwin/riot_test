from fastapi.testclient import TestClient
import pytest
from app.main import app

client = TestClient(app)


@pytest.mark.parametrize(
    "input",
    [
        {},
        "{False}",
        "{1}",
        "{None}",
        "toto",
        {"msg": "Hello World"},
        {"foo": "foobar", "bar": {"isBar": True}},
    ],
)
def test_encrypt_decrypt(input):
    encrypt_response = client.post("/encrypt", json=input)

    assert encrypt_response.status_code == 200

    print(encrypt_response.json())
    decrypt_response = client.post("/decrypt", json=encrypt_response.json())

    assert decrypt_response.status_code == 200

    assert decrypt_response.json() == input


def test_decrypt_invalid():
    input = {"key": "YWJjZA==", "val": "a"}
    decrypt_response = client.post("/decrypt", json=input)

    assert decrypt_response.status_code == 200

    assert decrypt_response.json() == {"key": "abcd", "val": "a"}


def test_sign_verify():
    input = '{"string"}'
    sign_response = client.post("/sign", json=input)

    assert sign_response.status_code == 200

    print(sign_response.content)
    verify_response = client.post(
        "/verify", json={"signature": sign_response.json(), "data": input}
    )
