"""AES-256 cryptographic engine for PICRYPT.

Phase 2 implements the required password-to-key design:
    password + salt -> SHA-256 -> 32-byte AES key
    AES-256-CBC with PKCS7 padding
    payload includes MAGIC, VERSION, SALT, IV, LENGTH, CIPHERTEXT

This module intentionally does not connect to Kivy or image handling.
"""

from __future__ import annotations

import hashlib
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from utils.payload import create_payload, parse_payload
from utils.validation import validate_iv, validate_message, validate_password, validate_payload, validate_salt


class AESCrypto:
    """Small AES helper class wrapping the Phase 2 public API."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        return derive_key(password, salt)

    @staticmethod
    def generate_salt() -> bytes:
        return generate_salt()

    @staticmethod
    def generate_iv() -> bytes:
        return generate_iv()

    @staticmethod
    def encrypt_message(password: str, message: str) -> bytes:
        return encrypt_message(password, message)

    @staticmethod
    def decrypt_message(password: str, payload: bytes) -> str:
        return decrypt_message(password, payload)

    @staticmethod
    def create_payload(salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        return create_payload(salt, iv, ciphertext)

    @staticmethod
    def parse_payload(payload: bytes):
        return parse_payload(payload)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive the 32-byte AES key using SHA-256 over password + salt.

    Design requirement:
        salt = 16 random bytes
        key = SHA256(password_bytes + salt)

    The digest length is exactly 32 bytes, which is valid for AES-256.
    """
    validate_password(password)
    validate_salt(salt)
    password_bytes = password.encode("utf-8")
    return hashlib.sha256(password_bytes + salt).digest()


def generate_salt() -> bytes:
    """Generate a cryptographically secure 16-byte salt."""
    return secrets.token_bytes(16)


def generate_iv() -> bytes:
    """Generate a cryptographically secure 16-byte IV for AES-CBC."""
    return secrets.token_bytes(16)


def encrypt_message(password: str, message: str) -> bytes:
    """Encrypt a UTF-8 message using AES-256-CBC and PKCS7 padding.

    Returns a serialized PICRYPT payload containing:
        magic, version, salt, iv, ciphertext_length, ciphertext
    """
    validate_password(password)
    validate_message(message)

    salt = generate_salt()
    iv = generate_iv()
    key = derive_key(password, salt)

    padded_message = pad(message.encode("utf-8"), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_message)

    return create_payload(salt, iv, ciphertext)


def decrypt_message(password: str, payload: bytes) -> str:
    """Decrypt a PICRYPT payload and return the original UTF-8 message."""
    validate_password(password)
    validate_payload(payload)

    parsed = parse_payload(payload)
    salt = parsed["salt"]
    iv = parsed["iv"]
    ciphertext = parsed["ciphertext"]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
    except ValueError as exc:
        raise ValueError("Decryption failed: invalid padding or wrong password.") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decryption failed: plaintext is not valid UTF-8.") from exc
