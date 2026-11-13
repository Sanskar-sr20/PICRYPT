"""Android document-picker and app-cache helpers.

The module keeps Android-only imports inside the picker operations so desktop
startup does not require pyjnius.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Callable

from kivy.utils import platform

PathCallback = Callable[[Path | None], None]
_next_request_code = 4100


def is_android() -> bool:
    return platform == "android"


def _mime_types(filters: list[str]) -> list[str]:
    extensions = {Path(pattern.replace("*", "file")).suffix.lower() for pattern in filters}
    mime_types = []
    image_extensions = extensions & {".png", ".jpg", ".jpeg"}
    if image_extensions:
        mime_types.append("image/png" if image_extensions == {".png"} else "image/*")
    if ".pdf" in extensions:
        mime_types.append("application/pdf")
    if ".mp4" in extensions:
        mime_types.append("video/mp4")
    return mime_types or ["*/*"]


def _suffix_for_uri(uri, filters: list[str], mime_types: list[str]) -> str:
    name = str(uri.getLastPathSegment() or "")
    suffix = Path(name).suffix.lower()
    allowed_suffixes = {
        Path(pattern.replace("*", "file")).suffix.lower()
        for pattern in filters
    }
    if suffix in allowed_suffixes:
        return suffix
    mime_to_suffix = {
        "image/png": ".png",
        "application/pdf": ".pdf",
        "video/mp4": ".mp4",
    }
    for mime_type in mime_types:
        if mime_type in mime_to_suffix:
            return mime_to_suffix[mime_type]
    return ""


def _cache_directory() -> Path:
    from jnius import autoclass

    activity = autoclass("org.kivy.android.PythonActivity").mActivity
    cache = Path(str(activity.getCacheDir().getAbsolutePath())) / "picrypt"
    cache.mkdir(parents=True, exist_ok=True)
    return cache


def _copy_uri_to_cache(uri, suffix: str) -> Path:
    from jnius import autoclass

    activity = autoclass("org.kivy.android.PythonActivity").mActivity
    resolver = activity.getContentResolver()
    stream = resolver.openInputStream(uri)
    if stream is None:
        raise OSError("Android document could not be opened.")
    try:
        descriptor, name = tempfile.mkstemp(prefix="picrypt-input-", suffix=suffix, dir=_cache_directory())
        with os.fdopen(descriptor, "wb") as output:
            buffer = bytearray(64 * 1024)
            while True:
                count = stream.read(buffer)
                if count <= 0:
                    break
                output.write(buffer[:count])
        return Path(name)
    finally:
        stream.close()


def _copy_file_to_uri(source: Path, uri) -> None:
    from jnius import autoclass

    activity = autoclass("org.kivy.android.PythonActivity").mActivity
    stream = activity.getContentResolver().openOutputStream(uri)
    if stream is None:
        raise OSError("Android document could not be created.")
    try:
        with source.open("rb") as input_file:
            while True:
                chunk = input_file.read(64 * 1024)
                if not chunk:
                    break
                stream.write(chunk)
    finally:
        stream.close()


def _start_activity(intent, callback: Callable[[object | None], None]) -> None:
    global _next_request_code
    from jnius import autoclass

    activity = autoclass("org.kivy.android.PythonActivity").mActivity
    request_code = _next_request_code
    _next_request_code += 1

    def on_activity_result(request, result, result_intent) -> None:
        if request != request_code:
            return
        activity.unbind(on_activity_result=on_activity_result)
        callback(result_intent if result == -1 else None)

    activity.bind(on_activity_result=on_activity_result)
    activity.startActivityForResult(intent, request_code)


def open_document(filters: list[str], callback: PathCallback) -> None:
    """Open an Android document and copy it into the app cache."""
    if not is_android():
        raise RuntimeError("Android document picker is only available on Android.")

    from jnius import autoclass

    Intent = autoclass("android.content.Intent")
    intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
    intent.addCategory(Intent.CATEGORY_OPENABLE)
    mime_types = _mime_types(filters)
    intent.setType(mime_types[0] if len(mime_types) == 1 else "*/*")
    if len(mime_types) > 1:
        intent.putExtra(Intent.EXTRA_MIME_TYPES, mime_types)

    def complete(result_intent) -> None:
        if result_intent is None:
            callback(None)
            return
        uri = result_intent.getData()
        if uri is None:
            callback(None)
            return
        try:
            suffix = _suffix_for_uri(uri, filters, mime_types)
            callback(_copy_uri_to_cache(uri, suffix))
        except (OSError, ValueError):
            callback(None)

    _start_activity(intent, complete)


def create_document(source: Path, display_name: str, mime_type: str, callback: PathCallback) -> None:
    """Export a generated cache file through the Android document picker."""
    if not is_android():
        raise RuntimeError("Android document picker is only available on Android.")

    from jnius import autoclass

    Intent = autoclass("android.content.Intent")
    intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
    intent.addCategory(Intent.CATEGORY_OPENABLE)
    intent.setType(mime_type)
    intent.putExtra(Intent.EXTRA_TITLE, display_name)

    def complete(result_intent) -> None:
        if result_intent is None:
            callback(None)
            return
        uri = result_intent.getData()
        if uri is None:
            callback(None)
            return
        try:
            _copy_file_to_uri(source, uri)
            callback(source)
        except OSError:
            callback(None)

    _start_activity(intent, complete)
