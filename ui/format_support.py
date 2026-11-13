"""Format-aware GUI dispatch for PICRYPT carrier services."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from picrypt.pdf_service import decrypt_pdf, encrypt_pdf
from picrypt.service import decrypt_image, encrypt_image
from kivy.utils import platform

FORMAT_OPTIONS = ("PNG", "JPEG", "PDF", "MP4")
ANDROID_FORMAT_OPTIONS = ("PNG", "PDF")
FORMAT_FILTERS = {
    "PNG": ["*.png", "*.PNG"],
    "JPEG": ["*.jpg", "*.JPG", "*.jpeg", "*.JPEG"],
    "PDF": ["*.pdf", "*.PDF"],
    "MP4": ["*.mp4", "*.MP4"],
}
FORMAT_EXTENSIONS = {"PNG": ".png", "JPEG": ".jpg", "PDF": ".pdf", "MP4": ".mp4"}
OUTPUT_ARGUMENTS = {
    "PNG": "output_image",
    "JPEG": "output_jpeg",
    "PDF": "output_pdf",
    "MP4": "output_mp4",
}

PathValue = str | os.PathLike[str]

if platform != "android":
    from picrypt.jpeg_service import decrypt_jpeg, encrypt_jpeg
    from picrypt.mp4_service import decrypt_mp4, encrypt_mp4


def available_format_options() -> tuple[str, ...]:
    return ANDROID_FORMAT_OPTIONS if platform == "android" else FORMAT_OPTIONS


def unsupported_on_android(format_name: str) -> bool:
    return platform == "android" and format_name not in ANDROID_FORMAT_OPTIONS


def unavailable_format_message(format_name: str) -> str:
    if unsupported_on_android(format_name):
        return f"{format_name} is not supported on Android yet. Choose PNG or PDF."
    return ""


def format_file_label(format_name: str) -> str:
    return "IMAGE" if format_name in {"PNG", "JPEG"} else format_name


def no_file_selected_label(format_name: str) -> str:
    label = format_file_label(format_name)
    return "No image selected" if label == "IMAGE" else f"No {label} selected"


def selected_file_label(format_name: str, prefix: str) -> str:
    return f"{prefix} {format_file_label(format_name)}"


def unique_output_path(input_path: PathValue, format_name: str) -> Path:
    source = Path(input_path)
    extension = extension_for_format(format_name)
    candidate = source.parent / f"PICRYPT_stego{extension}"
    index = 1
    while candidate.exists():
        candidate = source.parent / f"PICRYPT_stego_{index}{extension}"
        index += 1
    return candidate


def filters_for_format(format_name: str) -> list[str]:
    try:
        return FORMAT_FILTERS[format_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported PICRYPT format: {format_name}") from exc


def extension_for_format(format_name: str) -> str:
    try:
        return FORMAT_EXTENSIONS[format_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported PICRYPT format: {format_name}") from exc


def encrypt_for_format(
    format_name: str,
    input_path: PathValue,
    message: str,
    password: str,
    output_path: PathValue | None = None,
) -> Path:
    if unsupported_on_android(format_name):
        raise ValueError(unavailable_format_message(format_name))
    services: dict[str, Callable[..., Path]] = {"PNG": encrypt_image, "PDF": encrypt_pdf}
    if platform != "android":
        services.update({"JPEG": encrypt_jpeg, "MP4": encrypt_mp4})
    try:
        if output_path is None:
            return services[format_name](input_path, message=message, password=password)
        return services[format_name](
            input_path,
            **{
                OUTPUT_ARGUMENTS[format_name]: output_path,
                "message": message,
                "password": password,
            },
        )
    except KeyError as exc:
        raise ValueError(f"Unsupported PICRYPT format: {format_name}") from exc


def decrypt_for_format(format_name: str, input_path: PathValue, password: str) -> str:
    if unsupported_on_android(format_name):
        raise ValueError(unavailable_format_message(format_name))
    services: dict[str, Callable[..., str]] = {"PNG": decrypt_image, "PDF": decrypt_pdf}
    if platform != "android":
        services.update({"JPEG": decrypt_jpeg, "MP4": decrypt_mp4})
    try:
        return services[format_name](input_path, password)
    except KeyError as exc:
        raise ValueError(f"Unsupported PICRYPT format: {format_name}") from exc
