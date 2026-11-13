"""PDF content-stream steganography for PICRYPT.

This module appends a non-rendering stream to the first PDF page. Bits are
encoded by equivalent PDF numeric spellings in move-to commands:
``0 0 m`` stores zero and ``00 0 m`` stores one. The commands are enclosed in
``q``/``Q`` graphics-state operators and do not paint anything.

The embedded frame is:

    MAGIC (11 bytes) = b"PICRYPT-PDF"
    VERSION (1 byte) = 1
    PAYLOAD_LENGTH (4 bytes, big-endian)
    CRC32 (4 bytes, big-endian)
    EXISTING PICRYPT PAYLOAD (variable)

The maximum encrypted payload is deliberately capped at 64 KiB. PDF editors,
optimizers, and rewriting tools may normalize numeric spellings or regenerate
content streams, so this technique is not robust against PDF rewriting.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct
from typing import Iterator
import zlib

from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject

FRAME_MAGIC = b"PICRYPT-PDF"
FRAME_VERSION = 1
FRAME_HEADER = struct.Struct(f"!{len(FRAME_MAGIC)}sBII")
MAX_PAYLOAD_BYTES = 64 * 1024
STREAM_PREFIX = b"q 1 0 0 1 0 0 cm "
STREAM_SUFFIX = b"Q\n"
ZERO_TOKEN = b"0 0 m "
ONE_TOKEN = b"00 0 m "


def _path(value: str | os.PathLike[str], description: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"{description} must be a file path.")
    result = Path(value)
    if not result.name:
        raise ValueError(f"{description} is invalid.")
    return result


def _reader(input_pdf: str | os.PathLike[str]) -> PdfReader:
    path = _path(input_pdf, "PDF input")
    try:
        reader = PdfReader(str(path), strict=True)
    except Exception as exc:
        raise ValueError("Input is not a valid PDF.") from exc
    if not reader.pages:
        raise ValueError("PDF must contain at least one page.")
    return reader


def _frame(payload: bytes) -> bytes:
    if not payload:
        raise ValueError("Payload cannot be empty.")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("PDF payload exceeds the 64 KiB capacity limit.")
    header = FRAME_HEADER.pack(FRAME_MAGIC, FRAME_VERSION, len(payload), zlib.crc32(payload))
    return header + payload


def _bits(data: bytes) -> Iterator[int]:
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _encoded_stream(frame: bytes) -> bytes:
    tokens = (ONE_TOKEN if bit else ZERO_TOKEN for bit in _bits(frame))
    return STREAM_PREFIX + b"".join(tokens) + STREAM_SUFFIX


def _page_content(page) -> bytes:
    contents = page.get_contents()
    return b"" if contents is None else contents.get_data()


def _candidate_positions(data: bytes) -> Iterator[int]:
    start = 0
    while True:
        position = data.find(STREAM_PREFIX, start)
        if position < 0:
            return
        yield position + len(STREAM_PREFIX)
        start = position + 1


def _read_token(data: bytes, position: int) -> tuple[int, int]:
    if data.startswith(ONE_TOKEN, position):
        return 1, position + len(ONE_TOKEN)
    if data.startswith(ZERO_TOKEN, position):
        return 0, position + len(ZERO_TOKEN)
    raise ValueError("PDF payload contains an invalid bit token.")


def _read_bits(data: bytes, position: int, count: int) -> tuple[bytes, int]:
    values = []
    for _ in range(count):
        bit, position = _read_token(data, position)
        values.append(bit)
    output = bytearray()
    for offset in range(0, len(values), 8):
        value = 0
        for bit in values[offset : offset + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output), position


def calculate_capacity(input_pdf: str | os.PathLike[str]) -> int:
    """Return the explicit maximum payload size after validating the PDF."""
    _reader(input_pdf)
    return MAX_PAYLOAD_BYTES


def embed_payload(
    input_pdf: str | os.PathLike[str],
    payload: bytes,
    output_pdf: str | os.PathLike[str],
) -> None:
    """Append a framed encrypted payload to the first page of a PDF."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes.")
    output_path = _path(output_pdf, "PDF output")
    frame = _frame(bytes(payload))
    reader = _reader(input_pdf)
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)
    page = writer.pages[0]

    stream = DecodedStreamObject()
    stream.set_data(_page_content(page) + _encoded_stream(frame))
    page[NameObject("/Contents")] = writer._add_object(stream)
    try:
        with output_path.open("wb") as output:
            writer.write(output)
    except OSError as exc:
        raise ValueError("PDF output could not be saved.") from exc


def extract_payload(input_pdf: str | os.PathLike[str]) -> bytes:
    """Extract and validate the framed payload from the first PDF page."""
    reader = _reader(input_pdf)
    data = _page_content(reader.pages[0])
    for position in _candidate_positions(data):
        try:
            header_bytes, payload_position = _read_bits(data, position, FRAME_HEADER.size * 8)
            magic, version, payload_length, expected_crc = FRAME_HEADER.unpack(header_bytes)
            if magic != FRAME_MAGIC or version != FRAME_VERSION:
                continue
            if payload_length > MAX_PAYLOAD_BYTES:
                raise ValueError("PDF payload length exceeds the capacity limit.")
            payload_bytes, payload_end = _read_bits(data, payload_position, payload_length * 8)
            if not data.startswith(STREAM_SUFFIX, payload_end):
                raise ValueError("PDF payload frame terminator is missing.")
            if zlib.crc32(payload_bytes) != expected_crc:
                raise ValueError("PDF payload checksum is invalid or corrupted.")
            return payload_bytes
        except (IndexError, struct.error, ValueError):
            continue
    raise ValueError("PDF does not contain a valid PICRYPT payload.")


class PDFSteganography:
    """Wrapper exposing the independent PDF content-stream API."""

    @staticmethod
    def calculate_capacity(input_pdf: str | os.PathLike[str]) -> int:
        return calculate_capacity(input_pdf)

    @staticmethod
    def embed_payload(input_pdf: str | os.PathLike[str], payload: bytes, output_pdf: str | os.PathLike[str]) -> None:
        embed_payload(input_pdf, payload, output_pdf)

    @staticmethod
    def extract_payload(input_pdf: str | os.PathLike[str]) -> bytes:
        return extract_payload(input_pdf)
