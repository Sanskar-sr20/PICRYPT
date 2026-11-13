"""Binary payload serialization for PICRYPT.

The payload format is deliberately simple and designed for later LSB embedding:

    MAGIC (7 bytes)   = b"PICRYPT"
    VERSION (1 byte)  = 1
    SALT (16 bytes)
    IV (16 bytes)
    LENGTH (4 bytes, big-endian) = ciphertext length
    CIPHERTEXT (variable)

This ensures the payload carries enough metadata to decrypt without exposing
plain text, password, or the raw AES key.
"""

from __future__ import annotations

from typing import Dict

from utils.constants import MAGIC_HEADER, PAYLOAD_VERSION, SALT_LENGTH, IV_LENGTH, LENGTH_FIELD_SIZE


class Payload:
    """Simple payload helper class wrapping serialization helpers."""

    @staticmethod
    def create_payload(salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        return create_payload(salt, iv, ciphertext)

    @staticmethod
    def parse_payload(payload: bytes) -> Dict[str, object]:
        return parse_payload(payload)


def create_payload(salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Serialize PICRYPT payload metadata and ciphertext into one binary blob."""
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("Salt must be bytes.")
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError("IV must be bytes.")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes.")

    salt_bytes = bytes(salt)
    iv_bytes = bytes(iv)
    ciphertext_bytes = bytes(ciphertext)

    if len(salt_bytes) != SALT_LENGTH:
        raise ValueError(f"Salt must be exactly {SALT_LENGTH} bytes.")
    if len(iv_bytes) != IV_LENGTH:
        raise ValueError(f"IV must be exactly {IV_LENGTH} bytes.")

    length = len(ciphertext_bytes)
    if length > 0xFFFFFFFF:
        raise ValueError("Ciphertext is too large for the fixed payload length field.")

    length_field = length.to_bytes(LENGTH_FIELD_SIZE, byteorder="big", signed=False)
    return MAGIC_HEADER + bytes([PAYLOAD_VERSION]) + salt_bytes + iv_bytes + length_field + ciphertext_bytes


def parse_payload(payload: bytes) -> Dict[str, object]:
    """Deserialize a PICRYPT payload and validate its metadata."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes.")

    payload_bytes = bytes(payload)
    if len(payload_bytes) < (len(MAGIC_HEADER) + 1 + SALT_LENGTH + IV_LENGTH + LENGTH_FIELD_SIZE):
        raise ValueError("Payload is too short to contain a valid PICRYPT header.")

    magic = payload_bytes[: len(MAGIC_HEADER)]
    version = payload_bytes[len(MAGIC_HEADER)]
    salt_start = len(MAGIC_HEADER) + 1
    salt_end = salt_start + SALT_LENGTH
    iv_end = salt_end + IV_LENGTH
    length_end = iv_end + LENGTH_FIELD_SIZE

    if magic != MAGIC_HEADER:
        raise ValueError("Payload magic header is invalid.")
    if version != PAYLOAD_VERSION:
        raise ValueError(f"Unsupported payload version: {version}.")

    salt = payload_bytes[salt_start:salt_end]
    iv = payload_bytes[salt_end:iv_end]
    ciphertext_length = int.from_bytes(payload_bytes[iv_end:length_end], byteorder="big", signed=False)
    ciphertext = payload_bytes[length_end:]

    if len(ciphertext) != ciphertext_length:
        raise ValueError("Payload length does not match the stored ciphertext length.")

    return {
        "magic": magic,
        "version": version,
        "salt": salt,
        "iv": iv,
        "ciphertext_length": ciphertext_length,
        "ciphertext": ciphertext,
    }
