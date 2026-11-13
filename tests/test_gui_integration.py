"""Focused tests for GUI format dispatch and chooser mappings."""

from pathlib import Path

import pytest

import ui.format_support as format_support
import ui.android_storage as android_storage


@pytest.mark.parametrize("format_name", format_support.FORMAT_OPTIONS)
def test_encrypt_dispatches_to_matching_service(monkeypatch, format_name: str):
    calls = []

    def fake_service(input_path, **kwargs):
        calls.append((input_path, kwargs))
        return Path("output" + format_support.extension_for_format(format_name))

    monkeypatch.setattr(format_support, {
        "PNG": "encrypt_image",
        "JPEG": "encrypt_jpeg",
        "PDF": "encrypt_pdf",
        "MP4": "encrypt_mp4",
    }[format_name], fake_service)

    result = format_support.encrypt_for_format(format_name, "carrier", "message", "password")

    assert result.suffix == format_support.extension_for_format(format_name)
    assert calls == [("carrier", {"message": "message", "password": "password"})]


@pytest.mark.parametrize("format_name", format_support.FORMAT_OPTIONS)
def test_decrypt_dispatches_to_matching_service(monkeypatch, format_name: str):
    calls = []

    def fake_service(input_path, password):
        calls.append((input_path, password))
        return "recovered"

    monkeypatch.setattr(format_support, {
        "PNG": "decrypt_image",
        "JPEG": "decrypt_jpeg",
        "PDF": "decrypt_pdf",
        "MP4": "decrypt_mp4",
    }[format_name], fake_service)

    assert format_support.decrypt_for_format(format_name, "stego", "password") == "recovered"
    assert calls == [("stego", "password")]


@pytest.mark.parametrize(
    ("format_name", "expected_filters", "expected_extension"),
    [
        ("PNG", ["*.png", "*.PNG"], ".png"),
        ("JPEG", ["*.jpg", "*.JPG", "*.jpeg", "*.JPEG"], ".jpg"),
        ("PDF", ["*.pdf", "*.PDF"], ".pdf"),
        ("MP4", ["*.mp4", "*.MP4"], ".mp4"),
    ],
)
def test_format_chooser_mapping(format_name, expected_filters, expected_extension):
    assert format_support.filters_for_format(format_name) == expected_filters
    assert format_support.extension_for_format(format_name) == expected_extension


@pytest.mark.parametrize(
    ("format_name", "expected_label"),
    [("PNG", "IMAGE"), ("JPEG", "IMAGE"), ("PDF", "PDF"), ("MP4", "MP4")],
)
def test_format_ui_labels(format_name, expected_label):
    assert format_support.format_file_label(format_name) == expected_label
    expected_selection = "No image selected" if expected_label == "IMAGE" else f"No {expected_label} selected"
    assert format_support.no_file_selected_label(format_name) == expected_selection


def test_unique_output_path_avoids_existing_files(tmp_path: Path):
    source = tmp_path / "carrier.pdf"
    source.touch()
    (tmp_path / "PICRYPT_stego.pdf").touch()
    (tmp_path / "PICRYPT_stego_1.pdf").touch()

    assert format_support.unique_output_path(source, "PDF") == tmp_path / "PICRYPT_stego_2.pdf"


def test_encrypt_dispatch_passes_explicit_output_path(monkeypatch, tmp_path: Path):
    calls = []

    def fake_service(input_path, **kwargs):
        calls.append((input_path, kwargs))
        return Path(kwargs["output_pdf"])

    monkeypatch.setattr(format_support, "encrypt_pdf", fake_service)
    output = tmp_path / "PICRYPT_stego_1.pdf"

    result = format_support.encrypt_for_format("PDF", "carrier.pdf", "message", "password", output)

    assert result == output
    assert calls == [
        (
            "carrier.pdf",
            {"output_pdf": output, "message": "message", "password": "password"},
        )
    ]


def test_android_exposes_only_supported_formats(monkeypatch):
    monkeypatch.setattr(format_support, "platform", "android")

    assert format_support.available_format_options() == ("PNG", "PDF")
    with pytest.raises(ValueError, match="JPEG is not supported on Android"):
        format_support.encrypt_for_format("JPEG", "carrier.jpg", "message", "password")
    with pytest.raises(ValueError, match="MP4 is not supported on Android"):
        format_support.decrypt_for_format("MP4", "stego.mp4", "password")


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        (["*.png", "*.PNG"], ["image/png"]),
        (["*.pdf", "*.PDF"], ["application/pdf"]),
        (["*.png", "*.pdf"], ["image/png", "application/pdf"]),
    ],
)
def test_android_picker_uses_specific_mime_types(filters, expected):
    assert android_storage._mime_types(filters) == expected


def test_android_picker_recovers_supported_suffix_when_provider_has_no_name():
    class Uri:
        def getLastPathSegment(self):
            return ""

    assert android_storage._suffix_for_uri(
        Uri(), ["*.pdf", "*.PDF"], ["application/pdf"]
    ) == ".pdf"
