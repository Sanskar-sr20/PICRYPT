"""Tests for coefficient-domain JPEG message steganography."""

from pathlib import Path

import jpeglib
import numpy as np
import pytest
from PIL import Image

from crypto.aes_crypto import encrypt_message
from picrypt.jpeg_service import decrypt_jpeg, encrypt_jpeg
from steganography.jpeg import embed_payload, extract_payload

PASSWORD = "JPEGPassword123!"
MESSAGE = "A secret message in JPEG coefficients."


def create_jpeg(path: Path, size: tuple[int, int] = (256, 256), quality: int = 90) -> None:
    Image.effect_noise(size, 100).convert("RGB").save(path, format="JPEG", quality=quality)


def eligible_indices(component: np.ndarray):
    for block_row in range(component.shape[0]):
        for block_column in range(component.shape[1]):
            for row in range(8):
                for column in range(1, 8):
                    if abs(int(component[block_row, block_column, row, column])) >= 2:
                        yield block_row, block_column, row, column


def test_jpeg_message_round_trip_and_valid_output(tmp_path: Path):
    source = tmp_path / "cover.jpg"
    output = tmp_path / "stego.jpg"
    create_jpeg(source)

    result = encrypt_jpeg(source, output, MESSAGE, PASSWORD)

    assert result == output
    with Image.open(output) as image:
        image.load()
        assert image.format == "JPEG"
        assert image.size == (256, 256)
    assert decrypt_jpeg(output, PASSWORD) == MESSAGE


def test_wrong_password_is_rejected(tmp_path: Path):
    source = tmp_path / "cover.jpg"
    output = tmp_path / "stego.jpg"
    create_jpeg(source)
    encrypt_jpeg(source, output, MESSAGE, PASSWORD)

    with pytest.raises(ValueError, match="Incorrect password or corrupted JPEG data"):
        decrypt_jpeg(output, "WrongPassword!")


def test_insufficient_capacity_is_rejected_before_output(tmp_path: Path):
    source = tmp_path / "tiny.jpg"
    output = tmp_path / "stego.jpg"
    Image.new("RGB", (8, 8), color=(128, 128, 128)).save(source, quality=95)

    with pytest.raises(ValueError, match="capacity"):
        encrypt_jpeg(source, output, MESSAGE, PASSWORD)
    assert not output.exists()


def test_invalid_input_and_extension_are_rejected(tmp_path: Path):
    missing = tmp_path / "missing.jpg"
    with pytest.raises(ValueError, match="does not exist"):
        encrypt_jpeg(missing, tmp_path / "out.jpg", MESSAGE, PASSWORD)

    invalid = tmp_path / "invalid.jpg"
    invalid.write_bytes(b"not a JPEG")
    with pytest.raises((ValueError, OSError)):
        encrypt_jpeg(invalid, tmp_path / "out.jpg", MESSAGE, PASSWORD)

    png = tmp_path / "cover.png"
    Image.new("RGB", (32, 32), color=(1, 2, 3)).save(png)
    with pytest.raises(ValueError, match="JPEG input"):
        encrypt_jpeg(png, tmp_path / "out.jpg", MESSAGE, PASSWORD)


def test_corrupted_payload_is_rejected(tmp_path: Path):
    source = tmp_path / "cover.jpg"
    output = tmp_path / "stego.jpg"
    create_jpeg(source)
    encrypt_jpeg(source, output, MESSAGE, PASSWORD)

    dct = jpeglib.read_dct(str(output))
    try:
        for component in (dct.Y, dct.Cb, dct.Cr):
            if component is None:
                continue
            location = next(eligible_indices(component))
            component[location] = int(component[location]) + (1 if component[location] > 0 else -1)
            break
        dct.write_dct(str(output))
    finally:
        dct.close()

    with pytest.raises(ValueError, match="Invalid PICRYPT JPEG data"):
        decrypt_jpeg(output, PASSWORD)


def test_original_image_is_preserved(tmp_path: Path):
    source = tmp_path / "cover.jpg"
    output = tmp_path / "stego.jpg"
    create_jpeg(source)
    before = source.read_bytes()

    encrypt_jpeg(source, output, MESSAGE, PASSWORD)

    assert source.read_bytes() == before


def test_repeated_embedding_round_trip(tmp_path: Path):
    source = tmp_path / "cover.jpg"
    first = tmp_path / "first.jpg"
    second = tmp_path / "second.jpg"
    payload = encrypt_message(PASSWORD, MESSAGE)
    create_jpeg(source)

    embed_payload(source, payload, first)
    embed_payload(first, payload, second)

    assert extract_payload(second) == payload
    assert decrypt_jpeg(second, PASSWORD) == MESSAGE


def test_ac_edge_values_round_trip_and_dc_coefficients_are_unchanged(tmp_path: Path):
    source = tmp_path / "cover.jpg"
    edge_source = tmp_path / "edge-source.jpg"
    output = tmp_path / "edge-stego.jpg"
    payload = encrypt_message(PASSWORD, MESSAGE)
    create_jpeg(source)

    dct = jpeglib.read_dct(str(source))
    try:
        dct.Y[0, 0, 0, 1:5] = np.array([2, -2, 3, -3], dtype=dct.Y.dtype)
        dct.write_dct(str(edge_source))
    finally:
        dct.close()

    original_dct = jpeglib.read_dct(str(edge_source))
    try:
        original_dc = {name: np.array(getattr(original_dct, name)[:, :, 0, 0], copy=True) for name in ("Y", "Cb", "Cr") if getattr(original_dct, name) is not None}
    finally:
        original_dct.close()

    embed_payload(edge_source, payload, output)
    assert extract_payload(output) == payload

    embedded_dct = jpeglib.read_dct(str(output))
    try:
        for name, dc_values in original_dc.items():
            assert np.array_equal(getattr(embedded_dct, name)[:, :, 0, 0], dc_values)
    finally:
        embedded_dct.close()


def test_output_collision_is_rejected(tmp_path: Path):
    source = tmp_path / "cover.jpg"
    output = tmp_path / "stego.jpg"
    create_jpeg(source)
    output.write_bytes(b"keep this")

    with pytest.raises(ValueError, match="already exists"):
        encrypt_jpeg(source, output, MESSAGE, PASSWORD)
