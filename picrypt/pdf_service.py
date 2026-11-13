"""High-level service for encrypted messages hidden in PDF content streams."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Union

from crypto.aes_crypto import decrypt_message, encrypt_message
from steganography.pdf import embed_payload, extract_payload
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
    if path.suffix.lower() != ".pdf":
        raise ValueError("PDF input must have a .pdf extension.")
    return path


def _validate_output(input_path: Path, value: PathValue | None) -> Path:
    output = input_path.parent / "PICRYPT_stego.pdf" if value is None else _path(value, "Output PDF")
    if output.suffix.lower() != ".pdf":
        raise ValueError("PDF output must have a .pdf extension.")
    try:
        if output.resolve() == input_path.resolve():
            raise ValueError("Output PDF must be different from the input PDF.")
    except OSError as exc:
        raise ValueError("Output PDF path is invalid.") from exc
    if output.exists():
        raise ValueError("Output PDF already exists.")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("Output PDF path is invalid.") from exc
    return output


def _temporary_output(output: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".picrypt-pdf-", suffix=".pdf", dir=output.parent)
    os.close(descriptor)
    return Path(name)


def encrypt_pdf(
    input_pdf: PathValue,
    output_pdf: PathValue | None = None,
    message: str | None = None,
    password: str | None = None,
) -> Path:
    """Encrypt a message and embed it in a PDF without changing the input."""
    input_path = _validate_input(input_pdf, "Input PDF")
    output_path = _validate_output(input_path, output_pdf)
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
        raise ValueError("PDF output could not be saved.") from exc
    return output_path


def decrypt_pdf(stego_pdf: PathValue, password: str) -> str:
    """Extract and decrypt a message from a PDF content stream."""
    input_path = _validate_input(stego_pdf, "Stego PDF")
    validate_password(password)
    try:
        payload = extract_payload(input_path)
        parse_payload(payload)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("Invalid PICRYPT PDF data.") from exc
    try:
        return decrypt_message(password, payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("Incorrect password or corrupted PDF data.") from exc
