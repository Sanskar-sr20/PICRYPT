"""High-level service API for authenticated binary-file encryption.

``encrypt_file`` writes a ``.picrypt`` container without changing the input.
``decrypt_file`` authenticates that container and restores the encrypted
original filename by default. Existing output files are rejected to avoid
accidental overwrite; writes use a temporary file followed by ``os.replace``.
"""

from __future__ import annotations

import os
import tempfile
from os import PathLike
from pathlib import Path
from typing import Union

from crypto.file_crypto import decrypt_bytes, encrypt_bytes

PathValue = Union[str, PathLike[str]]


def _path_from_value(value: PathValue, description: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"{description} must be a file path.")
    path = Path(value)
    if not path.name:
        raise ValueError(f"{description} is invalid.")
    return path


def _validate_input(path_value: PathValue, description: str) -> Path:
    path = _path_from_value(path_value, description)
    if not path.exists() or not path.is_file():
        raise ValueError(f"{description} does not exist or is not a file.")
    return path


def _resolve_output(
    input_path: Path,
    output_value: PathValue | None,
    default_name: str,
) -> Path:
    output_path = (
        input_path.parent / default_name
        if output_value is None
        else _path_from_value(output_value, "Output file")
    )
    try:
        if output_path.resolve() == input_path.resolve():
            raise ValueError("Output file must be different from the input file.")
    except OSError as exc:
        raise ValueError("Output file path is invalid.") from exc
    if output_path.exists():
        raise ValueError("Output file already exists.")
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("Output file path is invalid.") from exc
    return output_path


def _atomic_write(output_path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".picrypt-",
        suffix=output_path.suffix or ".tmp",
        dir=output_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output_path)
    except OSError as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ValueError("Output file could not be saved.") from exc


def encrypt_file(
    input_file: PathValue,
    output_file: PathValue | None = None,
    password: str | None = None,
) -> Path:
    """Encrypt any binary file and return the new PICRYPT container path."""
    input_path = _validate_input(input_file, "Input file")
    output_path = _resolve_output(input_path, output_file, f"{input_path.name}.picrypt")
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    try:
        data = input_path.read_bytes()
    except OSError as exc:
        raise ValueError("Input file could not be read.") from exc
    container = encrypt_bytes(input_path.name, data, password)
    _atomic_write(output_path, container)
    return output_path


def decrypt_file(
    encrypted_file: PathValue,
    password: str | None = None,
    output_file: PathValue | None = None,
) -> Path:
    """Authenticate and decrypt a PICRYPT container to a binary file."""
    encrypted_path = _validate_input(encrypted_file, "Encrypted file")
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    try:
        container = encrypted_path.read_bytes()
    except OSError as exc:
        raise ValueError("Encrypted file could not be read.") from exc
    filename, data = decrypt_bytes(container, password)
    output_path = _resolve_output(encrypted_path, output_file, filename)
    _atomic_write(output_path, data)
    return output_path
