import hashlib
import os
from typing import Optional
from logger import logger

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB chunks


class FileHasher:
    """
    Cryptographic SHA-256 Fingerprint Engine.
    Uses chunked reading to calculate SHA-256 digests for files of any size
    without memory spikes, handling read errors gracefully.
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.chunk_size = chunk_size

    def calculate_sha256(self, file_path: str) -> Optional[str]:
        """
        Calculates hexadecimal SHA-256 digest of specified file.
        Returns hex string (e.g. 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        or None if file cannot be read or permission is denied.
        """
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            logger.warning(f"[FileHasher] Target is not a regular file: {abs_path}")
            return None

        sha256_hash = hashlib.sha256()

        try:
            with open(abs_path, "rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()

        except (PermissionError, OSError) as e:
            logger.error(f"[FileHasher] Error reading file for hashing {abs_path}: {e}")
            return None


def calculate_sha256(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Optional[str]:
    """Helper function to calculate SHA-256 digest of a file."""
    return FileHasher(chunk_size=chunk_size).calculate_sha256(file_path)
