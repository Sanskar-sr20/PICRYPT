"""High-level service for encrypted messages hidden in MP4 video frames."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Union

from crypto.aes_crypto import decrypt_message, encrypt_message
from steganography.mp4 import embed_payload, extract_payload
from utils.payload import parse_payload
from utils.validation import validate_message, validate_password

PathValue = Union[str, os.PathLike[str]]


def _path(value: PathValue, description: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"{description} must be a file path.")
    result = Path(value)
    if not result.name:
        raise ValueError(f"{description} is invalid.")
    return result


def _validate_input(value: PathValue, description: str) -> Path:
    path = _path(value, description)
    if not path.exists() or not path.is_file():
        raise ValueError(f"{description} does not exist or is not a file.")
    if path.suffix.lower() != ".mp4":
        raise ValueError("MP4 input must have a .mp4 extension.")
    return path


def _validate_output(input_path: Path, value: PathValue | None) -> Path:
    output = input_path.parent / "PICRYPT_stego.mp4" if value is None else _path(value, "Output MP4")
    if output.suffix.lower() != ".mp4":
        raise ValueError("MP4 output must have a .mp4 extension.")
    try:
        if output.resolve() == input_path.resolve():
            raise ValueError("Output MP4 must be different from the input MP4.")
    except OSError as exc:
        raise ValueError("Output MP4 path is invalid.") from exc
    if output.exists():
        raise ValueError("Output MP4 already exists.")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("Output MP4 path is invalid.") from exc
    return output


def _temporary_output(output: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".picrypt-mp4-", suffix=".mp4", dir=output.parent)
    os.close(descriptor)
    return Path(name)


def encrypt_mp4(
    input_mp4: PathValue,
    output_mp4: PathValue | None = None,
    message: str | None = None,
    password: str | None = None,
) -> Path:
    """Encrypt a message and hide it in an MP4 using frame-domain QIM."""
    input_path = _validate_input(input_mp4, "Input MP4")
    output_path = _validate_output(input_path, output_mp4)
    validate_message(message)
    validate_password(password)
    payload = encrypt_message(password, message)
    temporary_path = _temporary_output(output_path)
    try:
        embed_payload(input_path, payload, temporary_path)
        os.replace(temporary_path, output_path)
    except (OSError, TypeError, ValueError) as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(exc, ValueError):
            raise
        raise ValueError("MP4 output could not be saved.") from exc
    return output_path


def decrypt_mp4(stego_mp4: PathValue, password: str) -> str:
    """Extract and decrypt a message from an MP4 frame stream."""
    input_path = _validate_input(stego_mp4, "Stego MP4")
    validate_password(password)
    try:
        payload = extract_payload(input_path)
        parse_payload(payload)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("Invalid PICRYPT MP4 data.") from exc
    try:
        return decrypt_message(password, payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("Incorrect password or corrupted MP4 data.") from exc
