"""Phase 2 crypto tests for PICRYPT."""

import pytest

from crypto.aes_crypto import (
    decrypt_message,
    derive_key,
    encrypt_message,
    generate_iv,
    generate_salt,
)
from utils.payload import create_payload, parse_payload

PASSWORD = "StrongPassword123!"
MESSAGE = "This is a secret message for PICRYPT."


def test_key_length_is_32_bytes():
    salt = generate_salt()
    key = derive_key(PASSWORD, salt)
    assert len(key) == 32


def test_salt_length_is_16_bytes():
    salt = generate_salt()
    assert len(salt) == 16


def test_iv_length_is_16_bytes():
    iv = generate_iv()
    assert len(iv) == 16


def test_same_password_same_salt_same_key():
    salt = generate_salt()
    key_a = derive_key(PASSWORD, salt)
    key_b = derive_key(PASSWORD, salt)
    assert key_a == key_b


def test_different_salts_produce_different_keys():
    key_a = derive_key(PASSWORD, generate_salt())
    key_b = derive_key(PASSWORD, generate_salt())
    assert key_a != key_b


def test_encrypt_decrypt_round_trip_succeeds():
    payload = encrypt_message(PASSWORD, MESSAGE)
    assert isinstance(payload, bytes)
    assert decrypt_message(PASSWORD, payload) == MESSAGE


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        encrypt_message("", MESSAGE)
    with pytest.raises(ValueError):
        decrypt_message("", encrypt_message(PASSWORD, MESSAGE))


def test_empty_message_is_rejected():
    with pytest.raises(ValueError):
        encrypt_message(PASSWORD, "")


def test_wrong_password_fails():
    payload = encrypt_message(PASSWORD, MESSAGE)
    with pytest.raises(ValueError):
        decrypt_message("WrongPassword123!", payload)


def test_corrupted_ciphertext_fails():
    payload = encrypt_message(PASSWORD, MESSAGE)
    corrupted = bytearray(payload)
    corrupted[-1] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_message(PASSWORD, bytes(corrupted))


def test_payload_can_be_created_and_parsed_correctly():
    salt = generate_salt()
    iv = generate_iv()
    ciphertext = b"\x00\x01\x02\x03"
    payload = create_payload(salt, iv, ciphertext)
    parsed = parse_payload(payload)

    assert parsed["magic"] == b"PICRYPT"
    assert parsed["version"] == 1
    assert parsed["salt"] == salt
    assert parsed["iv"] == iv
    assert parsed["ciphertext"] == ciphertext


def test_payload_magic_validation_works():
    invalid_payload = b"INVALID\x01\x00\x00\x00\x00"
    with pytest.raises(ValueError):
        parse_payload(invalid_payload)


def test_payload_version_validation_works():
    payload = create_payload(generate_salt(), generate_iv(), b"test")
    payload = bytearray(payload)
    payload[7] = 99
    with pytest.raises(ValueError):
        parse_payload(bytes(payload))


def test_payload_length_validation_works():
    salt = generate_salt()
    iv = generate_iv()
    ciphertext = b"abcd"
    payload = bytearray(create_payload(salt, iv, ciphertext))
    payload[7 + 1 + 16 + 16] = 0x05
    with pytest.raises(ValueError):
        parse_payload(bytes(payload))


def test_same_message_same_password_use_different_salt_and_iv():
    payload_a = encrypt_message(PASSWORD, MESSAGE)
    payload_b = encrypt_message(PASSWORD, MESSAGE)

    parsed_a = parse_payload(payload_a)
    parsed_b = parse_payload(payload_b)

    assert parsed_a["salt"] != parsed_b["salt"]
    assert parsed_a["iv"] != parsed_b["iv"]


def test_plaintext_is_not_present_directly_inside_serialized_payload():
    payload = encrypt_message(PASSWORD, MESSAGE)
    assert MESSAGE.encode("utf-8") not in payload
