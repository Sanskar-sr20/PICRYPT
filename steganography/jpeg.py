"""Coefficient-domain JPEG steganography for PICRYPT.

JPEG policy:

* Components are traversed in Y, Cb, Cr order; absent chroma components are
  skipped.
* Within each component, blocks are traversed in array row-major order.
* Within each 8x8 block, only AC positions (rows 0..7, columns 1..7) are
  considered. DC coefficients at position (0, 0) are never read or changed.
* Only coefficients with absolute magnitude >= 2 are eligible. Their absolute
  magnitude parity stores one bit. A mismatching bit changes the magnitude by
  one, preserving sign and keeping the coefficient eligible. Values at the
  signed 16-bit limit are adjusted toward zero.

The embedded frame is not a replacement for the existing encrypted payload:

    MAGIC (11 bytes) = b"PICRYPT-JPG"
    VERSION (1 byte) = 1
    PAYLOAD_LENGTH (4 bytes, big-endian)
    PAYLOAD_CRC32 (4 bytes, big-endian)
    EXISTING PICRYPT PAYLOAD (variable)

The frame header supplies strict extraction bounds and the CRC detects damaged
coefficient data before the existing message decryption API is called.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any
import zlib

import jpeglib

FRAME_MAGIC = b"PICRYPT-JPG"
FRAME_VERSION = 1
FRAME_HEADER = struct.Struct(f"!{len(FRAME_MAGIC)}sBII")
MIN_ELIGIBLE_MAGNITUDE = 2
MAX_COEFFICIENT_MAGNITUDE = 32767
_COMPONENT_NAMES = ("Y", "Cb", "Cr")


def _load_dct(input_jpeg: str | os.PathLike[str]) -> Any:
    if not isinstance(input_jpeg, (str, os.PathLike)):
        raise TypeError("JPEG input must be a file path.")
    return jpeglib.read_dct(str(input_jpeg))


def _iter_eligible_coefficients(dct: Any) -> Iterator[tuple[Any, tuple[int, ...]]]:
    """Yield eligible AC coefficient locations in the shared traversal order."""
    for component_name in _COMPONENT_NAMES:
        component = getattr(dct, component_name, None)
        if component is None:
            continue
        for block_index in _block_indices(component.shape[:-2]):
            for row in range(8):
                for column in range(1, 8):
                    index = block_index + (row, column)
                    if abs(int(component[index])) >= MIN_ELIGIBLE_MAGNITUDE:
                        yield component, index


def _block_indices(shape: tuple[int, ...]) -> Iterator[tuple[int, ...]]:
    if len(shape) == 2:
        for row in range(shape[0]):
            for column in range(shape[1]):
                yield (row, column)
        return
    raise ValueError("JPEG DCT coefficient arrays must have two block dimensions.")


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("JPEG payload bit count must be divisible by eight.")
    output = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def _coefficient_bit(value: int) -> int:
    return abs(value) & 1


def _set_coefficient_bit(value: int, bit: int) -> int:
    if _coefficient_bit(value) == bit:
        return value
    magnitude = abs(value)
    if magnitude == MAX_COEFFICIENT_MAGNITUDE:
        magnitude -= 1
    else:
        magnitude += 1 if magnitude == MIN_ELIGIBLE_MAGNITUDE else -1
    return magnitude if value > 0 else -magnitude


def _frame(payload: bytes) -> bytes:
    if not payload:
        raise ValueError("Payload cannot be empty.")
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("Payload is too large for the JPEG frame.")
    header = FRAME_HEADER.pack(FRAME_MAGIC, FRAME_VERSION, len(payload), zlib.crc32(payload))
    return header + payload


def calculate_capacity(input_jpeg: str | os.PathLike[str]) -> int:
    """Return the number of payload bytes supported by eligible AC coefficients."""
    dct = _load_dct(input_jpeg)
    try:
        return sum(1 for _ in _iter_eligible_coefficients(dct)) // 8
    finally:
        dct.close()


def embed_payload(
    input_jpeg: str | os.PathLike[str],
    payload: bytes,
    output_jpeg: str | os.PathLike[str],
) -> None:
    """Embed an existing PICRYPT payload into JPEG AC coefficient parity."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes.")
    if not isinstance(output_jpeg, (str, os.PathLike)):
        raise TypeError("JPEG output must be a file path.")

    frame = _frame(bytes(payload))
    bits = _bytes_to_bits(frame)
    dct = _load_dct(input_jpeg)
    try:
        eligible = list(_iter_eligible_coefficients(dct))
        if len(bits) > len(eligible):
            raise ValueError("JPEG coefficient capacity is insufficient for the payload.")
        for (component, index), bit in zip(eligible, bits):
            component[index] = _set_coefficient_bit(int(component[index]), bit)
        dct.write_dct(str(output_jpeg))
    finally:
        dct.close()


def extract_payload(input_jpeg: str | os.PathLike[str]) -> bytes:
    """Extract, bounds-check, and CRC-check an existing PICRYPT payload."""
    dct = _load_dct(input_jpeg)
    try:
        eligible = list(_iter_eligible_coefficients(dct))
        header_bits_length = FRAME_HEADER.size * 8
        if len(eligible) < header_bits_length:
            raise ValueError("JPEG does not have enough eligible coefficients for a payload header.")

        header_bits = [_coefficient_bit(int(component[index])) for component, index in eligible[:header_bits_length]]
        magic, version, payload_length, expected_crc = FRAME_HEADER.unpack(_bits_to_bytes(header_bits))
        if magic != FRAME_MAGIC:
            raise ValueError("JPEG does not contain a valid PICRYPT JPEG payload.")
        if version != FRAME_VERSION:
            raise ValueError(f"Unsupported PICRYPT JPEG frame version: {version}.")

        total_bits = (FRAME_HEADER.size + payload_length) * 8
        if total_bits > len(eligible):
            raise ValueError("Declared JPEG payload length exceeds coefficient capacity.")
        payload_bits = [_coefficient_bit(int(component[index])) for component, index in eligible[:total_bits]]
        framed_payload = _bits_to_bytes(payload_bits)
        payload = framed_payload[FRAME_HEADER.size:]
        if zlib.crc32(payload) != expected_crc:
            raise ValueError("JPEG payload checksum is invalid or corrupted.")
        return payload
    finally:
        dct.close()


class JPEGSteganography:
    """Wrapper exposing the independent JPEG coefficient-domain API."""

    @staticmethod
    def calculate_capacity(input_jpeg: str | os.PathLike[str]) -> int:
        return calculate_capacity(input_jpeg)

    @staticmethod
    def embed_payload(input_jpeg: str | os.PathLike[str], payload: bytes, output_jpeg: str | os.PathLike[str]) -> None:
        embed_payload(input_jpeg, payload, output_jpeg)

    @staticmethod
    def extract_payload(input_jpeg: str | os.PathLike[str]) -> bytes:
        return extract_payload(input_jpeg)
