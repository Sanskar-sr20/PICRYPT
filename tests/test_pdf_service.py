"""Tests for PDF content-stream message steganography."""

from pathlib import Path

import pymupdf
from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject
import pytest

from crypto.aes_crypto import encrypt_message
from picrypt.pdf_service import decrypt_pdf, encrypt_pdf
from steganography.pdf import (
    FRAME_HEADER,
    MAX_PAYLOAD_BYTES,
    ONE_TOKEN,
    STREAM_PREFIX,
    ZERO_TOKEN,
    embed_payload,
)

PASSWORD = "PDFPassword123!"
MESSAGE = "A secret message in a PDF content stream."


def create_pdf(path: Path) -> None:
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=200)
    content = DecodedStreamObject()
    content.set_data(b"q 0 0 0 rg 40 40 180 100 re f Q\n")
    page[NameObject("/Contents")] = writer._add_object(content)
    with path.open("wb") as stream:
        writer.write(stream)


def render_page(path: Path) -> bytes:
    with pymupdf.open(path) as document:
        return document[0].get_pixmap(matrix=pymupdf.Matrix(2, 2), alpha=False).samples


def test_pdf_message_round_trip_and_rendering_is_unchanged(tmp_path: Path):
    source = tmp_path / "cover.pdf"
    output = tmp_path / "stego.pdf"
    create_pdf(source)
    before = render_page(source)

    result = encrypt_pdf(source, output, MESSAGE, PASSWORD)

    assert result == output
    assert decrypt_pdf(output, PASSWORD) == MESSAGE
    assert render_page(output) == before
    with pymupdf.open(output) as document:
        assert document.page_count == 1
    assert len(PdfReader(str(output)).pages) == 1


def test_wrong_password_is_rejected(tmp_path: Path):
    source = tmp_path / "cover.pdf"
    output = tmp_path / "stego.pdf"
    create_pdf(source)
    encrypt_pdf(source, output, MESSAGE, PASSWORD)

    with pytest.raises(ValueError, match="Incorrect password or corrupted PDF data"):
        decrypt_pdf(output, "WrongPassword!")


def test_invalid_pdf_is_rejected(tmp_path: Path):
    invalid = tmp_path / "invalid.pdf"
    invalid.write_bytes(b"not a PDF")

    with pytest.raises(ValueError, match="valid PDF"):
        encrypt_pdf(invalid, tmp_path / "output.pdf", MESSAGE, PASSWORD)

    with pytest.raises(ValueError, match="does not exist"):
        encrypt_pdf(tmp_path / "missing.pdf", tmp_path / "output.pdf", MESSAGE, PASSWORD)


def test_insufficient_capacity_is_rejected_before_output(tmp_path: Path):
    source = tmp_path / "cover.pdf"
    output = tmp_path / "stego.pdf"
    create_pdf(source)
    payload = encrypt_message(PASSWORD, MESSAGE)

    with pytest.raises(ValueError, match="64 KiB capacity"):
        embed_payload(source, payload + b"x" * (MAX_PAYLOAD_BYTES + 1), output)
    assert not output.exists()


def test_corrupted_payload_is_rejected(tmp_path: Path):
    source = tmp_path / "cover.pdf"
    output = tmp_path / "stego.pdf"
    create_pdf(source)
    encrypt_pdf(source, output, MESSAGE, PASSWORD)

    raw = output.read_bytes()
    marker = raw.find(STREAM_PREFIX)
    assert marker >= 0
    position = marker + len(STREAM_PREFIX)
    for _ in range(FRAME_HEADER.size * 8 + 8):
        if raw.startswith(ONE_TOKEN, position):
            position += len(ONE_TOKEN)
        else:
            assert raw.startswith(ZERO_TOKEN, position)
            position += len(ZERO_TOKEN)
    old_token = ONE_TOKEN if raw.startswith(ONE_TOKEN, position) else ZERO_TOKEN
    new_token = ZERO_TOKEN if old_token == ONE_TOKEN else ONE_TOKEN
    corrupted = raw[:position] + new_token + raw[position + len(old_token) :]
    output.write_bytes(corrupted)

    with pytest.raises(ValueError, match="Invalid PICRYPT PDF data"):
        decrypt_pdf(output, PASSWORD)


def test_original_pdf_is_preserved(tmp_path: Path):
    source = tmp_path / "cover.pdf"
    output = tmp_path / "stego.pdf"
    create_pdf(source)
    before = source.read_bytes()

    encrypt_pdf(source, output, MESSAGE, PASSWORD)

    assert source.read_bytes() == before


def test_output_collision_and_input_collision_are_rejected(tmp_path: Path):
    source = tmp_path / "cover.pdf"
    create_pdf(source)

    with pytest.raises(ValueError, match="different from the input"):
        encrypt_pdf(source, source, MESSAGE, PASSWORD)

    output = tmp_path / "stego.pdf"
    output.write_bytes(b"keep this")
    with pytest.raises(ValueError, match="already exists"):
        encrypt_pdf(source, output, MESSAGE, PASSWORD)


def test_non_pdf_output_extension_is_rejected(tmp_path: Path):
    source = tmp_path / "cover.pdf"
    create_pdf(source)

    with pytest.raises(ValueError, match=".pdf extension"):
        encrypt_pdf(source, tmp_path / "stego.txt", MESSAGE, PASSWORD)
