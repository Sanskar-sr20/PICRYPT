"""Tests for frame-domain MP4 message steganography."""

from fractions import Fraction
from pathlib import Path

import av
import numpy as np
import pytest

from picrypt.mp4_service import decrypt_mp4, encrypt_mp4
from steganography.mp4 import calculate_capacity, extract_payload

PASSWORD = "MP4Password123!"
MESSAGE = "A secret message in H.264 video frames."
FRAME_COUNT = 32
FRAME_SIZE = (128, 96)


def create_video(path: Path, frame_count: int = FRAME_COUNT, size: tuple[int, int] = FRAME_SIZE) -> None:
    width, height = size
    container = av.open(str(path), mode="w", format="mp4")
    stream = container.add_stream("libx264", rate=5)
    stream.width = width
    stream.height = height
    stream.pix_fmt = "yuv420p"
    stream.options = {"crf": "18", "preset": "ultrafast"}
    y_grid, x_grid = np.mgrid[:height, :width]
    for index in range(frame_count):
        frame = np.empty((height, width, 3), dtype=np.uint8)
        frame[:, :, 0] = (x_grid * 3 + index * 7) % 256
        frame[:, :, 1] = (y_grid * 5 + index * 11) % 256
        frame[:, :, 2] = ((x_grid + y_grid) * 2 + index * 13) % 256
        frame[8 + index % 24 : 16 + index % 24, 8:24, :] = 240
        video_frame = av.VideoFrame.from_ndarray(frame, format="rgb24")
        video_frame.pts = index
        video_frame.time_base = Fraction(1, 5)
        for packet in stream.encode(video_frame):
            container.mux(packet)
    for packet in stream.encode():
        container.mux(packet)
    container.close()


def decode_video(path: Path) -> list[np.ndarray]:
    container = av.open(str(path), mode="r")
    frames = [frame.to_ndarray(format="rgb24") for frame in container.decode(video=0)]
    container.close()
    return frames


def write_decoded_frames(path: Path, frames: list[np.ndarray]) -> None:
    height, width, _ = frames[0].shape
    container = av.open(str(path), mode="w", format="mp4")
    stream = container.add_stream("libx264", rate=5)
    stream.width = width
    stream.height = height
    stream.pix_fmt = "yuv420p"
    stream.options = {"crf": "18", "preset": "ultrafast"}
    for index, array in enumerate(frames):
        frame = av.VideoFrame.from_ndarray(array, format="rgb24")
        frame.pts = index
        frame.time_base = Fraction(1, 5)
        for packet in stream.encode(frame):
            container.mux(packet)
    for packet in stream.encode():
        container.mux(packet)
    container.close()


def test_mp4_round_trip_output_validity_and_quality(tmp_path: Path):
    source = tmp_path / "carrier.mp4"
    output = tmp_path / "stego.mp4"
    create_video(source)
    source_frames = decode_video(source)
    before = source.read_bytes()

    result = encrypt_mp4(source, output, MESSAGE, PASSWORD)

    output_frames = decode_video(output)
    assert result == output
    assert output.stat().st_size > 0
    assert len(output_frames) == len(source_frames)
    assert all(frame.shape == source_frames[0].shape for frame in output_frames)
    assert decrypt_mp4(output, PASSWORD) == MESSAGE
    assert source.read_bytes() == before
    mean_absolute_error = np.mean(
        [np.abs(before_frame.astype(np.int16) - after_frame.astype(np.int16)) for before_frame, after_frame in zip(source_frames, output_frames)]
    )
    assert mean_absolute_error < 15.0


def test_wrong_password_is_rejected(tmp_path: Path):
    source = tmp_path / "carrier.mp4"
    output = tmp_path / "stego.mp4"
    create_video(source)
    encrypt_mp4(source, output, MESSAGE, PASSWORD)

    with pytest.raises(ValueError, match="Incorrect password or corrupted MP4 data"):
        decrypt_mp4(output, "WrongPassword!")


def test_invalid_mp4_is_rejected(tmp_path: Path):
    invalid = tmp_path / "invalid.mp4"
    invalid.write_bytes(b"not an MP4")

    with pytest.raises(ValueError, match="Invalid MP4|decodable MP4"):
        encrypt_mp4(invalid, tmp_path / "out.mp4", MESSAGE, PASSWORD)

    with pytest.raises(ValueError, match="does not exist"):
        encrypt_mp4(tmp_path / "missing.mp4", tmp_path / "out.mp4", MESSAGE, PASSWORD)


def test_insufficient_capacity_is_rejected_before_output(tmp_path: Path):
    source = tmp_path / "tiny.mp4"
    output = tmp_path / "stego.mp4"
    create_video(source, frame_count=2, size=(8, 8))

    with pytest.raises(ValueError, match="capacity"):
        encrypt_mp4(source, output, MESSAGE, PASSWORD)
    assert not output.exists()


def test_corrupted_payload_is_rejected(tmp_path: Path):
    source = tmp_path / "carrier.mp4"
    output = tmp_path / "stego.mp4"
    corrupted = tmp_path / "corrupted.mp4"
    create_video(source)
    encrypt_mp4(source, output, MESSAGE, PASSWORD)

    frames = decode_video(output)
    frames[0][:] = 0
    frames[1][:] = 0
    write_decoded_frames(corrupted, frames)

    with pytest.raises(ValueError, match="Invalid PICRYPT MP4 data"):
        decrypt_mp4(corrupted, PASSWORD)


def test_deterministic_extraction_and_capacity(tmp_path: Path):
    source = tmp_path / "carrier.mp4"
    output = tmp_path / "stego.mp4"
    create_video(source)
    encrypt_mp4(source, output, MESSAGE, PASSWORD)

    first = extract_payload(output)
    second = extract_payload(output)
    assert first == second
    assert calculate_capacity(source) >= len(first)


def test_frame_geometry_and_order_are_preserved(tmp_path: Path):
    source = tmp_path / "carrier.mp4"
    output = tmp_path / "stego.mp4"
    create_video(source)
    encrypt_mp4(source, output, MESSAGE, PASSWORD)

    source_frames = decode_video(source)
    output_frames = decode_video(output)
    assert len(output_frames) == len(source_frames)
    assert [frame.shape for frame in output_frames] == [frame.shape for frame in source_frames]


def test_output_collision_and_input_collision_are_rejected(tmp_path: Path):
    source = tmp_path / "carrier.mp4"
    output = tmp_path / "stego.mp4"
    create_video(source)
    output.write_bytes(b"keep")

    with pytest.raises(ValueError, match="already exists"):
        encrypt_mp4(source, output, MESSAGE, PASSWORD)
    with pytest.raises(ValueError, match="different from the input"):
        encrypt_mp4(source, source, MESSAGE, PASSWORD)


def test_non_mp4_extension_is_rejected(tmp_path: Path):
    source = tmp_path / "carrier.mp4"
    create_video(source)

    with pytest.raises(ValueError, match=".mp4 extension"):
        encrypt_mp4(source, tmp_path / "stego.mov", MESSAGE, PASSWORD)
