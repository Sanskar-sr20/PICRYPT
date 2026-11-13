"""Frame-domain MP4 steganography using luminance DCT/QIM.

The module decodes frames with PyAV, embeds one bit per deterministic 8x8
luminance block, and re-encodes the result with the fixed libx264/yuv420p
pipeline used by this project. It does not use metadata, appended bytes, or
pixel LSBs.

Traversal policy:

* Every decoded video frame is visited in decode order.
* Each frame is converted to RGB, then to luminance.
* Complete 8x8 blocks are visited row-major from the top-left corner.
* Coefficients (2, 3) and (3, 2) in each block form the embedded difference.
* The difference is quantized into even/odd bins of QIM_STEP.

The frame is MAGIC, VERSION, PAYLOAD_LENGTH, CRC32, and the existing PICRYPT
payload. This technique is intended to survive this module's own H.264 encode
pipeline only; arbitrary transcoding, resizing, cropping, frame-rate changes,
or codec changes are unsupported.
"""

from __future__ import annotations

from fractions import Fraction
import os
from pathlib import Path
import struct
from typing import Iterator
import zlib

import av
import numpy as np

FRAME_MAGIC = b"PICRYPT-MP4"
FRAME_VERSION = 1
FRAME_HEADER = struct.Struct(f"!{len(FRAME_MAGIC)}sBII")
MAX_PAYLOAD_BYTES = 4096
QIM_STEP = 48.0
VIDEO_CODEC = "libx264"
VIDEO_PIXEL_FORMAT = "yuv420p"
VIDEO_CRF = "18"
VIDEO_PRESET = "ultrafast"

_DCT = np.empty((8, 8), dtype=np.float64)
for _row in range(8):
    for _column in range(8):
        scale = (1.0 / np.sqrt(8.0)) if _row == 0 else 0.5
        _DCT[_row, _column] = scale * np.cos(np.pi * (2 * _column + 1) * _row / 16.0)


def _bits_from_bytes(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _bytes_from_bits(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("MP4 payload bit count must be divisible by eight.")
    result = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        result.append(value)
    return bytes(result)


def _frame_payload(payload: bytes) -> bytes:
    if not payload:
        raise ValueError("Payload cannot be empty.")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("MP4 payload exceeds the 4 KiB capacity limit.")
    header = FRAME_HEADER.pack(FRAME_MAGIC, FRAME_VERSION, len(payload), zlib.crc32(payload))
    return header + payload


def _luminance(rgb_frame: np.ndarray) -> np.ndarray:
    return (
        rgb_frame[:, :, 0].astype(np.float64) * 0.299
        + rgb_frame[:, :, 1].astype(np.float64) * 0.587
        + rgb_frame[:, :, 2].astype(np.float64) * 0.114
    )


def _block_layout(height: int, width: int) -> tuple[int, int, int]:
    block_rows = height // 8
    block_columns = width // 8
    return block_rows, block_columns, block_rows * block_columns


def _blocks_from_luminance(luminance: np.ndarray) -> np.ndarray:
    block_rows, block_columns, _ = _block_layout(*luminance.shape)
    cropped = luminance[: block_rows * 8, : block_columns * 8]
    return cropped.reshape(block_rows, 8, block_columns, 8).transpose(0, 2, 1, 3).reshape(-1, 8, 8)


def _luminance_from_blocks(blocks: np.ndarray, height: int, width: int) -> np.ndarray:
    block_rows, block_columns, _ = _block_layout(height, width)
    cropped = blocks.reshape(block_rows, block_columns, 8, 8).transpose(0, 2, 1, 3).reshape(block_rows * 8, block_columns * 8)
    result = np.zeros((height, width), dtype=np.float64)
    result[: block_rows * 8, : block_columns * 8] = cropped
    if height > block_rows * 8:
        result[block_rows * 8 :, :] = result[block_rows * 8 - 1 : block_rows * 8, :]
    if width > block_columns * 8:
        result[:, block_columns * 8 :] = result[:, block_columns * 8 - 1 : block_columns * 8]
    return result


def _dct_blocks(blocks: np.ndarray) -> np.ndarray:
    return np.einsum("ij,njk,kl->nil", _DCT, blocks, _DCT.T)


def _idct_blocks(coefficients: np.ndarray) -> np.ndarray:
    return np.einsum("ij,njk,kl->nil", _DCT.T, coefficients, _DCT)


def _embed_bit(coefficients: np.ndarray, bit: int) -> None:
    difference = float(coefficients[2, 3] - coefficients[3, 2])
    target = 2.0 * QIM_STEP * np.rint(difference / (2.0 * QIM_STEP)) + bit * QIM_STEP
    adjustment = target - difference
    coefficients[2, 3] += adjustment / 2.0
    coefficients[3, 2] -= adjustment / 2.0


def _extract_bit(coefficients: np.ndarray) -> int:
    difference = float(coefficients[2, 3] - coefficients[3, 2])
    return int(np.rint(difference / QIM_STEP)) & 1


def _iter_block_coefficients(rgb_frame: np.ndarray) -> Iterator[np.ndarray]:
    luminance = _luminance(rgb_frame)
    coefficients = _dct_blocks(_blocks_from_luminance(luminance))
    for coefficient in coefficients:
        yield coefficient


def _modify_frame(rgb_frame: np.ndarray, bits: list[int]) -> np.ndarray:
    height, width, _ = rgb_frame.shape
    luminance = _luminance(rgb_frame)
    blocks = _blocks_from_luminance(luminance)
    coefficients = _dct_blocks(blocks)
    for coefficient, bit in zip(coefficients, bits):
        _embed_bit(coefficient, bit)
    modified_luminance = _luminance_from_blocks(_idct_blocks(coefficients), height, width)
    delta = modified_luminance - luminance
    modified = np.clip(rgb_frame.astype(np.float64) + delta[:, :, None], 0, 255)
    return np.rint(modified).astype(np.uint8)


def _read_frames(input_mp4: str | os.PathLike[str]) -> tuple[list[np.ndarray], Fraction]:
    try:
        container = av.open(str(input_mp4), mode="r")
        video_streams = [stream for stream in container.streams if stream.type == "video"]
        if len(video_streams) != 1:
            raise ValueError("MP4 must contain exactly one video stream.")
        stream = video_streams[0]
        rate = stream.average_rate
        if rate is None or rate <= 0:
            raise ValueError("MP4 video stream must have a valid frame rate.")
        frames: list[np.ndarray] = []
        previous_pts = None
        for frame in container.decode(video=0):
            if frame.pts is None or (previous_pts is not None and frame.pts < previous_pts):
                raise ValueError("MP4 frame timestamps must be present and ordered.")
            previous_pts = frame.pts
            array = frame.to_ndarray(format="rgb24")
            if array.ndim != 3 or array.shape[2] != 3 or array.dtype != np.uint8:
                raise ValueError("MP4 frames must decode to uint8 RGB arrays.")
            frames.append(array)
        container.close()
    except av.error.FFmpegError as exc:
        raise ValueError("Input is not a valid decodable MP4.") from exc
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Input is not a valid decodable MP4.") from exc
    if not frames:
        raise ValueError("MP4 must contain at least one video frame.")
    height, width, _ = frames[0].shape
    if height < 8 or width < 8:
        raise ValueError("MP4 frames must be at least 8x8 pixels.")
    if any(frame.shape != frames[0].shape for frame in frames):
        raise ValueError("MP4 frame dimensions must remain constant.")
    return frames, Fraction(rate)


def _encode_frames(output_mp4: str | os.PathLike[str], frames: list[np.ndarray], rate: Fraction) -> None:
    height, width, _ = frames[0].shape
    try:
        container = av.open(str(output_mp4), mode="w", format="mp4")
        stream = container.add_stream(VIDEO_CODEC, rate=rate)
        stream.width = width
        stream.height = height
        stream.pix_fmt = VIDEO_PIXEL_FORMAT
        stream.options = {"crf": VIDEO_CRF, "preset": VIDEO_PRESET}
        for index, array in enumerate(frames):
            frame = av.VideoFrame.from_ndarray(array, format="rgb24")
            frame.pts = index
            frame.time_base = Fraction(1, rate)
            for packet in stream.encode(frame):
                container.mux(packet)
        for packet in stream.encode():
            container.mux(packet)
        container.close()
    except Exception as exc:
        raise ValueError("MP4 output could not be encoded.") from exc


def _validate_encoded_output(output_mp4: str | os.PathLike[str], expected_shape: tuple[int, int, int], expected_count: int) -> None:
    frames, _ = _read_frames(output_mp4)
    if len(frames) != expected_count or any(frame.shape != expected_shape for frame in frames):
        raise ValueError("Encoded MP4 geometry or frame count changed.")


def calculate_capacity(input_mp4: str | os.PathLike[str]) -> int:
    """Return the maximum framed payload bytes for a decoded MP4."""
    frames, _ = _read_frames(input_mp4)
    _, _, blocks = _block_layout(frames[0].shape[0], frames[0].shape[1])
    return min(MAX_PAYLOAD_BYTES, max(0, frames.__len__() * blocks // 8 - FRAME_HEADER.size))


def embed_payload(
    input_mp4: str | os.PathLike[str],
    payload: bytes,
    output_mp4: str | os.PathLike[str],
) -> None:
    """Embed an existing PICRYPT payload and validate the final MP4."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes.")
    framed = _frame_payload(bytes(payload))
    frames, rate = _read_frames(input_mp4)
    bits = _bits_from_bytes(framed)
    _, _, blocks = _block_layout(frames[0].shape[0], frames[0].shape[1])
    if len(bits) > len(frames) * blocks:
        raise ValueError("MP4 frame capacity is insufficient for the payload.")

    modified_frames: list[np.ndarray] = []
    bit_offset = 0
    for frame in frames:
        remaining = bits[bit_offset : bit_offset + blocks]
        modified_frames.append(_modify_frame(frame, remaining) if remaining else frame)
        bit_offset += len(remaining)
    _encode_frames(output_mp4, modified_frames, rate)
    _validate_encoded_output(output_mp4, frames[0].shape, len(frames))


def extract_payload(input_mp4: str | os.PathLike[str]) -> bytes:
    """Extract and validate the framed payload from a decoded MP4."""
    frames, _ = _read_frames(input_mp4)
    block_coefficients = [coefficient for frame in frames for coefficient in _iter_block_coefficients(frame)]
    header_bits_count = FRAME_HEADER.size * 8
    if len(block_coefficients) < header_bits_count:
        raise ValueError("MP4 does not have enough capacity for a payload header.")
    header = _bytes_from_bits([_extract_bit(coefficient) for coefficient in block_coefficients[:header_bits_count]])
    magic, version, payload_length, expected_crc = FRAME_HEADER.unpack(header)
    if magic != FRAME_MAGIC:
        raise ValueError("MP4 does not contain a valid PICRYPT payload.")
    if version != FRAME_VERSION:
        raise ValueError(f"Unsupported MP4 payload version: {version}.")
    if payload_length > MAX_PAYLOAD_BYTES:
        raise ValueError("MP4 payload exceeds the 4 KiB capacity limit.")
    total_bits = (FRAME_HEADER.size + payload_length) * 8
    if total_bits > len(block_coefficients):
        raise ValueError("Declared MP4 payload length exceeds frame capacity.")
    payload = _bytes_from_bits([_extract_bit(coefficient) for coefficient in block_coefficients[:total_bits]])[FRAME_HEADER.size:]
    if zlib.crc32(payload) != expected_crc:
        raise ValueError("MP4 payload checksum is invalid or corrupted.")
    return payload
