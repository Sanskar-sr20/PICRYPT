"""Focused tests for authenticated binary-file encryption."""

from pathlib import Path

import pytest

from picrypt.file_service import decrypt_file, encrypt_file

PASSWORD = "FilePassword123!"


def test_binary_round_trip_preserves_exact_bytes(tmp_path: Path):
    source = tmp_path / "sample.bin"
    original = bytes(range(256)) * 3 + b"\x00\xff\x10"
    source.write_bytes(original)

    encrypted = encrypt_file(source, password=PASSWORD)
    restored = decrypt_file(encrypted, password=PASSWORD, output_file=tmp_path / "restored" / "sample.bin")

    assert restored == tmp_path / "restored" / "sample.bin"
    assert restored.read_bytes() == original


@pytest.mark.parametrize("filename", ["sample.pdf", "sample.mp3", "sample.mp4"])
def test_representative_binary_extensions_round_trip(tmp_path: Path, filename: str):
    source = tmp_path / filename
    original = b"synthetic binary fixture\x00\x01\xfe" * 20
    source.write_bytes(original)

    encrypted = encrypt_file(source, password=PASSWORD)
    restored = decrypt_file(encrypted, password=PASSWORD, output_file=tmp_path / "restored" / filename)

    assert restored.name == filename
    assert restored.read_bytes() == original


def test_empty_file_round_trip(tmp_path: Path):
    source = tmp_path / "empty.dat"
    source.write_bytes(b"")

    encrypted = encrypt_file(source, password=PASSWORD)
    restored = decrypt_file(encrypted, password=PASSWORD, output_file=tmp_path / "restored" / "empty.dat")

    assert restored.read_bytes() == b""


def test_wrong_password_is_rejected(tmp_path: Path):
    source = tmp_path / "secret.bin"
    source.write_bytes(b"secret bytes")
    encrypted = encrypt_file(source, password=PASSWORD)

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_file(encrypted, password="WrongPassword!")


def test_ciphertext_tampering_is_rejected(tmp_path: Path):
    source = tmp_path / "secret.bin"
    source.write_bytes(b"secret bytes")
    encrypted = encrypt_file(source, password=PASSWORD)
    tampered = bytearray(encrypted.read_bytes())
    tampered[-17] ^= 0xFF
    encrypted.write_bytes(tampered)

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_file(encrypted, password=PASSWORD)


def test_truncated_container_is_rejected(tmp_path: Path):
    source = tmp_path / "secret.bin"
    source.write_bytes(b"secret bytes")
    encrypted = encrypt_file(source, password=PASSWORD)
    encrypted.write_bytes(encrypted.read_bytes()[:-1])

    with pytest.raises(ValueError, match="truncated|invalid length"):
        decrypt_file(encrypted, password=PASSWORD)


def test_invalid_magic_is_rejected(tmp_path: Path):
    source = tmp_path / "secret.bin"
    source.write_bytes(b"secret bytes")
    encrypted = encrypt_file(source, password=PASSWORD)
    container = bytearray(encrypted.read_bytes())
    container[0] ^= 0xFF
    encrypted.write_bytes(container)

    with pytest.raises(ValueError, match="Invalid PICRYPT file header"):
        decrypt_file(encrypted, password=PASSWORD)


def test_unsupported_version_is_rejected(tmp_path: Path):
    source = tmp_path / "secret.bin"
    source.write_bytes(b"secret bytes")
    encrypted = encrypt_file(source, password=PASSWORD)
    container = bytearray(encrypted.read_bytes())
    container[12] = 99
    encrypted.write_bytes(container)

    with pytest.raises(ValueError, match="Unsupported PICRYPT file version"):
        decrypt_file(encrypted, password=PASSWORD)


def test_invalid_paths_and_collisions_are_rejected(tmp_path: Path):
    missing = tmp_path / "missing.bin"
    with pytest.raises(ValueError, match="does not exist"):
        encrypt_file(missing, password=PASSWORD)

    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    with pytest.raises(ValueError, match="different from the input"):
        encrypt_file(source, source, PASSWORD)

    output = tmp_path / "existing.picrypt"
    output.write_bytes(b"already here")
    with pytest.raises(ValueError, match="already exists"):
        encrypt_file(source, output, PASSWORD)


def test_original_file_is_unchanged_and_encryptions_are_randomized(tmp_path: Path):
    source = tmp_path / "source.bin"
    original = b"unchanged input" * 100
    source.write_bytes(original)
    first = tmp_path / "first.picrypt"
    second = tmp_path / "second.picrypt"

    encrypt_file(source, first, PASSWORD)
    encrypt_file(source, second, PASSWORD)

    assert source.read_bytes() == original
    assert first.read_bytes() != second.read_bytes()


def test_filename_is_encrypted_and_explicit_decrypt_output_is_supported(tmp_path: Path):
    source = tmp_path / "private-report.pdf"
    source.write_bytes(b"report contents")
    encrypted = encrypt_file(source, password=PASSWORD)
    container = encrypted.read_bytes()

    assert source.name.encode("utf-8") not in container
    explicit_output = tmp_path / "restored.bin"
    assert decrypt_file(encrypted, PASSWORD, explicit_output) == explicit_output
    assert explicit_output.read_bytes() == source.read_bytes()


def test_decrypt_output_collision_is_rejected(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    encrypted = encrypt_file(source, password=PASSWORD)
    restored = tmp_path / "restored.bin"
    restored.write_bytes(b"keep me")

    with pytest.raises(ValueError, match="already exists"):
        decrypt_file(encrypted, PASSWORD, restored)
