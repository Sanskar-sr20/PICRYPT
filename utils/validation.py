"""Validation helpers for PICRYPT."""

from __future__ import annotations

from utils.constants import IV_LENGTH, SALT_LENGTH


def validate_non_empty(value: str) -> bool:
    """Return True when the value is not empty or whitespace only."""
    return value is not None and value.strip() != ""


def validate_password(password: str) -> None:
    """Reject missing or invalid password values."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not validate_non_empty(password):
        raise ValueError("Password cannot be empty.")


def validate_message(message: str) -> None:
    """Reject missing or invalid message values."""
    if not isinstance(message, str):
        raise TypeError("Message must be a string.")
    if not validate_non_empty(message):
        raise ValueError("Message cannot be empty.")


def validate_salt(salt: bytes) -> None:
    """Validate the salt length."""
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("Salt must be bytes.")
    if len(bytes(salt)) != SALT_LENGTH:
        raise ValueError(f"Salt must be exactly {SALT_LENGTH} bytes.")


def validate_iv(iv: bytes) -> None:
    """Validate the IV length."""
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError("IV must be bytes.")
    if len(bytes(iv)) != IV_LENGTH:
        raise ValueError(f"IV must be exactly {IV_LENGTH} bytes.")


def validate_payload(payload: bytes) -> None:
    """Validate the payload format before decrypting."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes.")
    if not payload:
        raise ValueError("Payload cannot be empty.")

    payload_bytes = bytes(payload)
    if payload_bytes[:7] != b"PICRYPT":
        raise ValueError("Payload magic header is invalid.")
