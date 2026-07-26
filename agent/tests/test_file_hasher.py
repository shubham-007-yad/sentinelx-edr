import hashlib
import os
import tempfile
import pytest
from file_hasher import FileHasher, calculate_sha256


def test_empty_file_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name

    try:
        digest = calculate_sha256(tmp_path)
        # Empty string SHA-256 is well known
        expected = hashlib.sha256(b"").hexdigest()
        assert digest == expected
        assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_chunked_reading_sha256():
    content = b"SentinelX EDR USB Forensic File Scanner Test " * 500
    expected = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Use small chunk size (64 bytes) to force multiple chunk reads
        hasher = FileHasher(chunk_size=64)
        digest = hasher.calculate_sha256(tmp_path)

        assert digest == expected
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_non_existent_file_sha256():
    digest = calculate_sha256("/invalid/path/to/missing_file.bin")
    assert digest is None


def test_directory_path_sha256():
    with tempfile.TemporaryDirectory() as tmpdir:
        digest = calculate_sha256(tmpdir)
        assert digest is None
