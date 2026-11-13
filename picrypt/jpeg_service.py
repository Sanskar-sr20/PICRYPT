"""High-level service for encrypted messages hidden in JPEG coefficients."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Union

from PIL import UnidentifiedImageError

from crypto.aes_crypto import decrypt_message, encrypt_message
from steganography.jpeg import embed_payload, extract_payload
from utils.payload import parse_payload
from utils.validation import validate_message, validate_password

JPEG_FORMATS = {".jpg", ".jpeg"}
PathValue = Union[str, os.PathLike[str]]


def _path_from_value(value: PathValue, description: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"{description} must be a file path.")
    path = Path(value)
    if not path.name:
        raise ValueError(f"{description} is invalid.")
    return path


def _validate_input(input_jpeg: PathValue, description: str) -> Path:
    path = _path_from_value(input_jpeg, description)
    if not path.exists() or not path.is_file():
        raise ValueError(f"{description} does not exist or is not a file.")
    if path.suffix.lower() not in JPEG_FORMATS:
        raise ValueError("JPEG input must have a .jpg or .jpeg extension.")
    return path


def _validate_output(input_path: Path, output_jpeg: PathValue | None) -> Path:
    output_path = input_path.parent / "PICRYPT_stego.jpg" if output_jpeg is None else _path_from_value(output_jpeg, "Output JPEG")
    if output_path.suffix.lower() not in JPEG_FORMATS:
        raise ValueError("JPEG output must have a .jpg or .jpeg extension.")
    try:
        if output_path.resolve() == input_path.resolve():
            raise ValueError("Output JPEG must be different from the input JPEG.")
    except OSError as exc:
        raise ValueError("Output JPEG path is invalid.") from exc
    if output_path.exists():
        raise ValueError("Output JPEG already exists.")
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("Output JPEG path is invalid.") from exc
    return output_path


def _temporary_output_path(output_path: Path) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".picrypt-jpeg-",
        suffix=output_path.suffix.lower(),
        dir=output_path.parent,
    )
    os.close(descriptor)
    return Path(temporary_name)


def encrypt_jpeg(
    input_jpeg: PathValue,
    output_jpeg: PathValue | None = None,
    message: str | None = None,
    password: str | None = None,
) -> Path:
    """Encrypt a message and embed it into a JPEG without changing the input."""
    input_path = _validate_input(input_jpeg, "Input JPEG")
    output_path = _validate_output(input_path, output_jpeg)
    validate_message(message)
    validate_password(password)
    payload = encrypt_message(password, message)
    temporary_path = _temporary_output_path(output_path)
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
        raise ValueError("JPEG output could not be saved.") from exc
    return output_path


def decrypt_jpeg(stego_jpeg: PathValue, password: str) -> str:
    """Extract and decrypt a message from a coefficient-domain JPEG."""
    input_path = _validate_input(stego_jpeg, "Stego JPEG")
    validate_password(password)
    try:
        payload = extract_payload(input_path)
        parse_payload(payload)
    except (OSError, TypeError, ValueError, UnidentifiedImageError) as exc:
        raise ValueError("Invalid PICRYPT JPEG data.") from exc
    try:
        return decrypt_message(password, payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("Incorrect password or corrupted JPEG data.") from exc
