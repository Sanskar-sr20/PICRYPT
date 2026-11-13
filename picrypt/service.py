"""High-level integration services for PICRYPT.

This module coordinates the existing crypto, payload, and steganography
modules. It does not implement a second encryption or LSB algorithm.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Union

from PIL import Image, UnidentifiedImageError

from crypto.aes_crypto import decrypt_message, encrypt_message
from steganography.lsb import calculate_capacity, embed_payload, extract_payload
from utils.constants import SUPPORTED_IMAGE_FORMATS
from utils.payload import parse_payload
from utils.validation import validate_message, validate_password

ImageInput = Union[str, os.PathLike[str], Image.Image]


def _path_from_value(value: Union[str, os.PathLike[str]], description: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"{description} must be a file path.")
    path = Path(value)
    if not path.name:
        raise ValueError(f"{description} is invalid.")
    return path


def _validate_input_image(input_image: ImageInput) -> Path | Image.Image:
    if isinstance(input_image, Image.Image):
        return input_image

    path = _path_from_value(input_image, "Input image")
    if not path.exists() or not path.is_file():
        raise ValueError("Please select an image.")
    if path.suffix.lower() not in SUPPORTED_IMAGE_FORMATS:
        raise ValueError("Unsupported image format.")

    try:
        with Image.open(path) as image:
            image.verify()
    except (OSError, UnidentifiedImageError) as exc:
        raise ValueError("Unable to open the selected image.") from exc
    return path


def _validate_output_path(
    input_image: Path | Image.Image,
    output_image: Union[str, os.PathLike[str], None],
) -> Path:
    if output_image is None:
        if isinstance(input_image, Path):
            output_path = input_image.parent / "PICRYPT_stego.png"
        else:
            output_path = Path.cwd() / "PICRYPT_stego.png"
    else:
        output_path = _path_from_value(output_image, "Output file")
        if output_path.suffix == "":
            output_path = output_path.with_suffix(".png")

    if output_path.suffix.lower() not in SUPPORTED_IMAGE_FORMATS:
        raise ValueError("Output image must be PNG, JPG, or JPEG.")

    if isinstance(input_image, Path):
        try:
            if output_path.resolve() == input_image.resolve():
                raise ValueError("Output image must be different from the cover image.")
        except OSError as exc:
            raise ValueError("Output file path is invalid.") from exc

    if output_path.exists() and output_path.is_dir():
        raise ValueError("Output file path is invalid.")

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("Output file path is invalid.") from exc

    return output_path


def _validate_capacity(input_image: Path | Image.Image, payload: bytes) -> None:
    try:
        capacity = calculate_capacity(input_image)
    except (OSError, UnidentifiedImageError) as exc:
        raise ValueError("Unable to open the selected image.") from exc
    if len(payload) > capacity:
        raise ValueError("Message is too large for this image.")


def _temporary_output_path(output_path: Path) -> Path:
    suffix = output_path.suffix.lower() or ".png"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".picrypt-",
        suffix=suffix,
        dir=output_path.parent,
    )
    os.close(descriptor)
    return Path(temporary_name)


def encrypt_image(
    input_image: ImageInput,
    output_image: Union[str, os.PathLike[str], None] = None,
    message: str | None = None,
    password: str | None = None,
) -> Path:
    """Encrypt a message, embed it into an image, and return the output path."""
    validated_input = _validate_input_image(input_image)
    output_path = _validate_output_path(validated_input, output_image)

    validate_message(message)
    validate_password(password)

    payload = encrypt_message(password, message)
    _validate_capacity(validated_input, payload)

    temporary_path = _temporary_output_path(output_path)
    try:
        embed_payload(validated_input, payload, temporary_path)
        os.replace(temporary_path, output_path)
    except (OSError, ValueError, TypeError) as exc:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(exc, ValueError):
            raise
        raise ValueError("Output file could not be saved.") from exc

    return output_path


def decrypt_image(stego_image: ImageInput, password: str) -> str:
    """Extract and decrypt a PICRYPT payload from a stego image."""
    validated_image = _validate_input_image(stego_image)
    validate_password(password)

    try:
        payload = extract_payload(validated_image)
        parse_payload(payload)
    except (OSError, UnidentifiedImageError, TypeError, ValueError) as exc:
        raise ValueError("Invalid PICRYPT data.") from exc

    try:
        return decrypt_message(password, payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("Incorrect password or corrupted data.") from exc
