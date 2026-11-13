"""Integration tests for the full PICRYPT crypto + steganography pipeline."""

from pathlib import Path

from PIL import Image

from crypto.aes_crypto import decrypt_message, encrypt_message
from steganography.lsb import embed_payload, extract_payload

PASSWORD = "SecurePass123!"
MESSAGE = "This message is hidden using PICRYPT and LSB."


def test_end_to_end_encryption_embedding_extraction_and_decryption(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    stego_path = tmp_path / "stego.png"

    cover = Image.new("RGB", (64, 64), color=(12, 34, 56))
    cover.save(cover_path)

    encrypted_payload = encrypt_message(PASSWORD, MESSAGE)
    embed_payload(cover_path, encrypted_payload, stego_path)

    recovered_payload = extract_payload(stego_path)
    recovered_message = decrypt_message(PASSWORD, recovered_payload)

    assert recovered_message == MESSAGE
    assert recovered_payload == encrypted_payload
