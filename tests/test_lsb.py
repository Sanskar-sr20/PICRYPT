"""LSB steganography tests for PICRYPT."""

from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

from crypto.aes_crypto import encrypt_message
from steganography.lsb import (
    bits_to_bytes,
    bytes_to_bits,
    calculate_capacity,
    embed_payload,
    extract_payload,
)
from utils.payload import create_payload


@pytest.fixture
def sample_image(tmp_path: Path) -> Path:
    image_path = tmp_path / "cover.png"
    image = Image.new("RGB", (32, 32), color=(255, 200, 100))
    image.save(image_path)
    return image_path


def make_valid_payload(payload_bytes: bytes) -> bytes:
    return create_payload(b"\x00" * 16, b"\x01" * 16, payload_bytes)


def test_small_payload_embedding_and_extraction(sample_image: Path):
    payload = make_valid_payload(b"PICRYPT-test-payload")
    output_path = sample_image.parent / "stego.png"

    embed_payload(sample_image, payload, output_path)
    recovered = extract_payload(output_path)

    assert recovered == payload


def test_empty_payload_rejected(sample_image: Path):
    with pytest.raises(ValueError):
        embed_payload(sample_image, b"", sample_image.parent / "empty.png")


def test_capacity_calculation(sample_image: Path):
    capacity = calculate_capacity(sample_image)
    assert capacity == (32 * 32 * 3) // 8


def test_exact_capacity_payload(sample_image: Path):
    capacity = calculate_capacity(sample_image)
    payload = make_valid_payload(b"A" * (capacity - 44))
    output_path = sample_image.parent / "max_capacity.png"

    embed_payload(sample_image, payload, output_path)
    recovered = extract_payload(output_path)

    assert recovered == payload


def test_oversized_payload_rejected(sample_image: Path):
    capacity = calculate_capacity(sample_image)
    payload = make_valid_payload(b"A" * (capacity - 43))
    with pytest.raises(ValueError):
        embed_payload(sample_image, payload, sample_image.parent / "oversized.png")


def test_png_round_trip(sample_image: Path):
    payload = make_valid_payload(b"PNG-roundtrip")
    output_path = sample_image.parent / "png_roundtrip.png"

    embed_payload(sample_image, payload, output_path)
    extracted = extract_payload(output_path)

    assert extracted == payload


def test_rgb_conversion(sample_image: Path):
    payload = make_valid_payload(b"rgb-check")
    output_path = sample_image.parent / "rgb_test.png"

    embed_payload(sample_image, payload, output_path)
    image = Image.open(output_path).convert("RGB")
    assert image.mode == "RGB"
    assert extract_payload(image) == payload


def test_invalid_image_handling(tmp_path: Path):
    bad_path = tmp_path / "not_an_image.txt"
    bad_path.write_text("not valid image data", encoding="utf-8")

    with pytest.raises(Exception):
        embed_payload(bad_path, b"abc", tmp_path / "bad_out.png")


def test_invalid_picrypt_magic_detection(sample_image: Path):
    image = Image.new("RGB", (16, 16), color=(0, 0, 0))
    output_path = sample_image.parent / "invalid_magic.png"

    embed_payload(image, b"NOT-PICRYPT", output_path)
    with pytest.raises(ValueError):
        extract_payload(output_path)


def test_incomplete_payload_detection(sample_image: Path):
    payload = bytearray(make_valid_payload(b"abc"))
    payload[40:44] = (7000).to_bytes(4, byteorder="big")
    image = Image.new("RGB", (128, 128), color=(0, 0, 0))
    output_path = sample_image.parent / "incomplete.png"

    embed_payload(image, bytes(payload), output_path)
    with pytest.raises(ValueError):
        extract_payload(output_path)


def test_extracted_payload_exactly_equals_original_payload(sample_image: Path):
    payload = make_valid_payload(b"exactly-equals-original")
    output_path = sample_image.parent / "exact_match.png"

    embed_payload(sample_image, payload, output_path)
    extracted = extract_payload(output_path)

    assert extracted == payload


def test_original_cover_image_is_not_modified(sample_image: Path):
    original = Image.open(sample_image).convert("RGB")
    original_pixels = list(original.get_flattened_data())
    payload = make_valid_payload(b"cover-not-modified")
    output_path = sample_image.parent / "preserve_cover.png"

    embed_payload(original, payload, output_path)
    preserved = list(Image.open(sample_image).convert("RGB").get_flattened_data())

    assert preserved == original_pixels


def test_same_pil_image_object_is_not_modified_and_returns_stego_copy():
    original = Image.new("RGB", (32, 32), color=(255, 200, 100))
    original_pixels = list(original.get_flattened_data())
    payload = make_valid_payload(b"same-object")

    stego = embed_payload(original, payload, original)

    assert list(original.get_flattened_data()) == original_pixels
    assert stego is not None
    assert extract_payload(stego) == payload


def test_higher_order_bits_remain_unchanged(sample_image: Path):
    original = Image.open(sample_image).convert("RGB")
    original_pixels = list(original.get_flattened_data())
    payload = make_valid_payload(b"higher-order-bits-stay")
    output_path = sample_image.parent / "higher_bits.png"

    embed_payload(original, payload, output_path)
    stego_pixels = list(Image.open(output_path).convert("RGB").get_flattened_data())

    for original_pixel, stego_pixel in zip(original_pixels, stego_pixels):
        for old_channel, new_channel in zip(original_pixel, stego_pixel):
            assert (old_channel & 0xFE) == (new_channel & 0xFE)


def test_different_payloads_embed_and_extract_correctly(sample_image: Path):
    first = make_valid_payload(b"alpha")
    second = make_valid_payload(b"beta-gamma-delta")
    output_a = sample_image.parent / "payload_a.png"
    output_b = sample_image.parent / "payload_b.png"

    embed_payload(sample_image, first, output_a)
    embed_payload(sample_image, second, output_b)

    assert extract_payload(output_a) == first
    assert extract_payload(output_b) == second


def test_phase2_payload_can_be_embedded_and_extracted_unchanged(sample_image: Path):
    encrypted_payload = encrypt_message("StrongPassword123!", "Debug secret message for LSB")
    output_path = sample_image.parent / "phase2_payload.png"

    embed_payload(sample_image, encrypted_payload, output_path)
    recovered = extract_payload(output_path)

    assert recovered == encrypted_payload


def test_bits_helpers_round_trip():
    payload = b"\x00\x01\x02\x03\x10\x20\x40\x80"
    bits = bytes_to_bits(payload)
    assert len(bits) == len(payload) * 8
    assert bits_to_bytes(bits) == payload
