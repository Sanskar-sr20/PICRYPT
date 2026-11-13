"""Authenticated binary-file encryption for PICRYPT.

The file container format is versioned and consists of:

    MAGIC (12 bytes)           = b"PICRYPT-FILE"
    VERSION (1 byte)           = 1
    SALT (16 bytes)
    NONCE (12 bytes)
    CIPHERTEXT_LENGTH (8 bytes, big-endian)
    CIPHERTEXT (variable)
    TAG (16 bytes)

The fixed header is authenticated as AES-GCM associated data. The encrypted
payload is a two-byte filename length, the UTF-8 original filename, and the
exact original file bytes. The filename is therefore not exposed in the
header. Keys are derived with scrypt using N=2**14, r=8, and p=1.
"""

from __future__ import annotations

import struct
from pathlib import Path
import secrets

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

from utils.validation import validate_password

MAGIC = b"PICRYPT-FILE"
VERSION = 1
SALT_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16
KEY_LENGTH = 32
KDF_N = 2**14
KDF_R = 8
KDF_P = 1
_HEADER = struct.Struct(f"!{len(MAGIC)}sB{SALT_LENGTH}s{NONCE_LENGTH}sQ")
_FILENAME_LENGTH = struct.Struct("!H")


def _derive_key(password: str, salt: bytes) -> bytes:
    validate_password(password)
    return scrypt(
        password.encode("utf-8"),
        salt,
        key_len=KEY_LENGTH,
        N=KDF_N,
        r=KDF_R,
        p=KDF_P,
    )


def encrypt_bytes(filename: str, data: bytes, password: str) -> bytes:
    """Return an authenticated PICRYPT container for arbitrary binary data."""
    if not isinstance(filename, str) or not filename or "\x00" in filename:
        raise ValueError("Filename must be a non-empty string without NUL bytes.")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("File data must be bytes.")

    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > 0xFFFF:
        raise ValueError("Filename is too long.")
    plaintext = _FILENAME_LENGTH.pack(len(filename_bytes)) + filename_bytes + bytes(data)
    salt = secrets.token_bytes(SALT_LENGTH)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    key = _derive_key(password, salt)
    header = _HEADER.pack(MAGIC, VERSION, salt, nonce, len(plaintext))

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return header + ciphertext + tag


def decrypt_bytes(container: bytes, password: str) -> tuple[str, bytes]:
    """Authenticate and decrypt a container, returning its filename and bytes."""
    if not isinstance(container, (bytes, bytearray)):
        raise TypeError("Encrypted file data must be bytes.")
    container_bytes = bytes(container)
    if len(container_bytes) < _HEADER.size + TAG_LENGTH:
        raise ValueError("Encrypted file is truncated.")

    header = container_bytes[: _HEADER.size]
    magic, version, salt, nonce, ciphertext_length = _HEADER.unpack(header)
    if magic != MAGIC:
        raise ValueError("Invalid PICRYPT file header.")
    if version != VERSION:
        raise ValueError(f"Unsupported PICRYPT file version: {version}.")

    expected_length = _HEADER.size + ciphertext_length + TAG_LENGTH
    if expected_length != len(container_bytes):
        raise ValueError("Encrypted file is truncated or has an invalid length.")
    if ciphertext_length < _FILENAME_LENGTH.size:
        raise ValueError("Encrypted file payload is malformed.")

    ciphertext = container_bytes[_HEADER.size : _HEADER.size + ciphertext_length]
    tag = container_bytes[-TAG_LENGTH:]
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
    cipher.update(header)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError("Unable to decrypt file: authentication failed.") from exc

    filename_length = _FILENAME_LENGTH.unpack(plaintext[: _FILENAME_LENGTH.size])[0]
    filename_end = _FILENAME_LENGTH.size + filename_length
    if filename_end > len(plaintext):
        raise ValueError("Encrypted file payload is malformed.")
    try:
        filename = plaintext[_FILENAME_LENGTH.size : filename_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Encrypted file payload has an invalid filename.") from exc
    if not filename or "\x00" in filename or Path(filename).name != filename:
        raise ValueError("Encrypted file payload has an invalid filename.")
    return filename, plaintext[filename_end:]
