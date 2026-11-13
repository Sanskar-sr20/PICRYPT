"""Phase 4 integration service tests for PICRYPT."""

from pathlib import Path

import pytest
from PIL import Image

from picrypt.service import decrypt_image, encrypt_image

PASSWORD = "ServicePassword123!"
MESSAGE = "A message handled by the Phase 4 service."


def create_cover(path: Path, size: tuple[int, int] = (128, 128)) -> None:
    Image.new("RGB", size, color=(25, 50, 75)).save(path)


def test_successful_encryption_creates_png_and_returns_path(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    output_path = tmp_path / "nested" / "PICRYPT_stego.png"
    create_cover(cover_path)

    result = encrypt_image(cover_path, output_path, MESSAGE, PASSWORD)

    assert result == output_path
    assert result.exists()
    with Image.open(result) as stego:
        assert stego.format == "PNG"
        assert stego.mode == "RGB"


def test_successful_decryption_returns_original_message(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    stego_path = tmp_path / "stego.png"
    create_cover(cover_path)

    encrypt_image(cover_path, stego_path, MESSAGE, PASSWORD)

    assert decrypt_image(stego_path, PASSWORD) == MESSAGE


def test_wrong_password_fails_safely(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    stego_path = tmp_path / "stego.png"
    create_cover(cover_path)
    encrypt_image(cover_path, stego_path, MESSAGE, PASSWORD)

    with pytest.raises(ValueError, match="Incorrect password or corrupted data"):
        decrypt_image(stego_path, "WrongPassword123!")


def test_empty_message_and_password_are_rejected(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    create_cover(cover_path)

    with pytest.raises(ValueError, match="Message cannot be empty"):
        encrypt_image(cover_path, tmp_path / "message.png", "", PASSWORD)
    with pytest.raises(ValueError, match="Password cannot be empty"):
        encrypt_image(cover_path, tmp_path / "password.png", MESSAGE, "")


def test_invalid_image_is_rejected(tmp_path: Path):
    invalid_path = tmp_path / "invalid.png"
    invalid_path.write_text("not an image", encoding="utf-8")

    with pytest.raises(ValueError, match="Unable to open the selected image"):
        encrypt_image(invalid_path, tmp_path / "stego.png", MESSAGE, PASSWORD)


def test_image_too_small_is_rejected_without_output(tmp_path: Path):
    cover_path = tmp_path / "tiny.png"
    output_path = tmp_path / "stego.png"
    create_cover(cover_path, (4, 4))

    with pytest.raises(ValueError, match="Message is too large for this image"):
        encrypt_image(cover_path, output_path, MESSAGE, PASSWORD)

    assert not output_path.exists()


def test_original_cover_remains_unchanged(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    stego_path = tmp_path / "stego.png"
    create_cover(cover_path)
    before = cover_path.read_bytes()

    encrypt_image(cover_path, stego_path, MESSAGE, PASSWORD)

    assert cover_path.read_bytes() == before


def test_output_equal_to_input_is_rejected(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    create_cover(cover_path)

    with pytest.raises(ValueError, match="different from the cover image"):
        encrypt_image(cover_path, cover_path, MESSAGE, PASSWORD)


def test_default_output_path_is_created(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cover_path = tmp_path / "cover.png"
    create_cover(cover_path)
    monkeypatch.chdir(tmp_path)

    result = encrypt_image(cover_path, message=MESSAGE, password=PASSWORD)

    assert result == tmp_path / "PICRYPT_stego.png"
    assert result.exists()


def test_multiple_encryptions_use_different_payload_randomness(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    first_path = tmp_path / "first.png"
    second_path = tmp_path / "second.png"
    create_cover(cover_path)

    encrypt_image(cover_path, first_path, MESSAGE, PASSWORD)
    encrypt_image(cover_path, second_path, MESSAGE, PASSWORD)

    assert first_path.read_bytes() != second_path.read_bytes()


def test_corrupted_stego_image_fails_safely(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    stego_path = tmp_path / "stego.png"
    create_cover(cover_path)
    encrypt_image(cover_path, stego_path, MESSAGE, PASSWORD)
    with Image.open(stego_path) as stego:
        corrupted = stego.convert("RGB")
    red, green, blue = corrupted.getpixel((0, 0))
    corrupted.putpixel((0, 0), (red ^ 1, green, blue))
    corrupted.save(stego_path)

    with pytest.raises(ValueError, match="Invalid PICRYPT data|Incorrect password or corrupted data"):
        decrypt_image(stego_path, PASSWORD)
