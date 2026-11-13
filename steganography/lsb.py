"""LSB steganography module for PICRYPT.

Phase 3 hides the serialized PICRYPT payload inside RGB image pixels using the
least significant bit of each color channel.

The cryptography module remains responsible for AES encryption/decryption.
This module only embeds and extracts the encrypted payload.
"""

from __future__ import annotations

import os
from typing import Iterable, List, Sequence, Union

from PIL import Image

from utils.constants import IV_LENGTH, MAGIC_HEADER, PAYLOAD_VERSION, SALT_LENGTH

PAYLOAD_HEADER_SIZE = len(MAGIC_HEADER) + 1 + SALT_LENGTH + IV_LENGTH + 4


class LSBSteganography:
    """Simple wrapper for the LSB embed/extract API."""

    @staticmethod
    def calculate_capacity(image: Union[str, os.PathLike[str], Image.Image]) -> int:
        return calculate_capacity(image)

    @staticmethod
    def bytes_to_bits(data: bytes) -> List[int]:
        return bytes_to_bits(data)

    @staticmethod
    def bits_to_bytes(bits: Sequence[int]) -> bytes:
        return bits_to_bytes(bits)

    @staticmethod
    def embed_payload(
        input_image: Union[str, os.PathLike[str], Image.Image],
        payload: bytes,
        output_image: Union[str, os.PathLike[str], Image.Image],
    ) -> Union[Image.Image, None]:
        return embed_payload(input_image, payload, output_image)

    @staticmethod
    def extract_payload(stego_image: Union[str, os.PathLike[str], Image.Image]) -> bytes:
        return extract_payload(stego_image)


def _load_rgb_image(image_or_path: Union[str, os.PathLike[str], Image.Image]) -> Image.Image:
    """Open an image and always return an RGB copy."""
    if isinstance(image_or_path, Image.Image):
        return image_or_path.copy().convert("RGB")

    if isinstance(image_or_path, (str, os.PathLike)):
        with Image.open(image_or_path) as opened:
            return opened.convert("RGB").copy()

    raise TypeError("Image input must be a PIL Image or a file path.")


def calculate_capacity(image: Union[str, os.PathLike[str], Image.Image]) -> int:
    """Return the maximum number of payload bytes that can be embedded in the image."""
    rgb_image = _load_rgb_image(image)
    capacity_bits = rgb_image.width * rgb_image.height * 3
    return capacity_bits // 8


def _get_pixels(image: Image.Image) -> list[tuple[int, int, int]]:
    """Return RGB pixels without using deprecated Pillow APIs when available."""
    get_flattened_data = getattr(image, "get_flattened_data", None)
    if get_flattened_data is not None:
        return list(get_flattened_data())
    return list(image.getdata())


def bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes into a list of bits in MSB-first order."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes.")

    bits: List[int] = []
    for byte in bytes(data):
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    """Convert a bit sequence back into bytes."""
    if len(bits) % 8 != 0:
        raise ValueError("Bit sequence length must be divisible by 8.")

    output = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i : i + 8]
        value = 0
        for bit in chunk:
            if bit not in (0, 1):
                raise ValueError("Bits must be 0 or 1 values.")
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def embed_payload(
    input_image: Union[str, os.PathLike[str], Image.Image],
    payload: bytes,
    output_image: Union[str, os.PathLike[str], Image.Image],
) -> Union[Image.Image, None]:
    """Embed a payload into the LSBs of the image.

    The payload is treated as opaque bytes; the Phase 2 payload format is not
    changed by the steganography phase.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("Payload must be bytes.")

    payload_bytes = bytes(payload)
    if not payload_bytes:
        raise ValueError("Payload cannot be empty.")

    rgb_image = _load_rgb_image(input_image)
    required_bits = len(payload_bytes) * 8
    available_bits = rgb_image.width * rgb_image.height * 3
    if required_bits > available_bits:
        raise ValueError("Image capacity is insufficient for the selected message.")

    bits = bytes_to_bits(payload_bytes)
    pixels = _get_pixels(rgb_image)
    updated_pixels = []
    bit_index = 0

    for pixel in pixels:
        channels = list(pixel)
        for channel_index in range(3):
            if bit_index < len(bits):
                channels[channel_index] = (channels[channel_index] & 0xFE) | bits[bit_index]
                bit_index += 1
        updated_pixels.append(tuple(channels))

    stego = Image.new("RGB", rgb_image.size)
    stego.putdata(updated_pixels)

    if isinstance(output_image, Image.Image):
        if output_image is input_image:
            return stego
        output_image.paste(stego)
        return

    if isinstance(output_image, (str, os.PathLike)):
        stego.save(output_image)
        return

    raise TypeError("Output target must be a file path or PIL Image object.")


def extract_payload(stego_image: Union[str, os.PathLike[str], Image.Image]) -> bytes:
    """Extract and return the serialized PICRYPT payload from a stego image."""
    rgb_image = _load_rgb_image(stego_image)
    pixels = _get_pixels(rgb_image)
    extracted_bits: List[int] = []

    for pixel in pixels:
        for channel in pixel:
            extracted_bits.append(channel & 1)

    if len(extracted_bits) < PAYLOAD_HEADER_SIZE * 8:
        raise ValueError("Image does not contain enough data for a valid PICRYPT payload.")

    header_bits = extracted_bits[: PAYLOAD_HEADER_SIZE * 8]
    header = bits_to_bytes(header_bits)

    if len(header) < PAYLOAD_HEADER_SIZE:
        raise ValueError("Incomplete payload header.")

    if header[: len(MAGIC_HEADER)] != MAGIC_HEADER:
        raise ValueError("Image does not contain a valid PICRYPT payload.")

    version = header[len(MAGIC_HEADER)]
    if version != PAYLOAD_VERSION:
        raise ValueError(f"Unsupported PICRYPT payload version: {version}.")

    length_start = len(MAGIC_HEADER) + 1 + SALT_LENGTH + IV_LENGTH
    length_end = length_start + 4
    payload_length = int.from_bytes(header[length_start:length_end], byteorder="big", signed=False)
    available_payload_bytes = len(extracted_bits) // 8
    total_required_bytes = PAYLOAD_HEADER_SIZE + payload_length
    if total_required_bytes > available_payload_bytes:
        raise ValueError("Declared payload length exceeds the available stego image capacity.")
    total_required_bits = total_required_bytes * 8

    if len(extracted_bits) < total_required_bits:
        raise ValueError("Incomplete payload detected in the stego image.")

    payload_bits = extracted_bits[:total_required_bits]
    payload = bits_to_bytes(payload_bits)

    if len(payload) != total_required_bytes:
        raise ValueError("Extracted payload size does not match the header length field.")

    return payload
