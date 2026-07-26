import os
import sys
from typing import List, Dict, Any, Generator, Optional, Tuple
from logger import logger


class USBScanner:
    """
    USB File Enumeration Engine.
    Recursively scans directory structures on mounted USB drives,
    discovering files while gracefully handling permission errors,
    broken symlinks, and OS level errors without crashing.
    """

    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self.scanned_files_count: int = 0
        self.skipped_files_count: int = 0
        self.errors_count: int = 0

    def enumerate_files(self) -> List[str]:
        """
        Recursively discovers every accessible file under target_path.
        Returns a list of absolute file paths.
        """
        return list(self.walk_files())

    def walk_files(self) -> Generator[str, None, None]:
        """
        Generator yielding absolute paths of every accessible file under target_path.
        Gracefully skips inaccessible files and directories.
        """
        self.scanned_files_count = 0
        self.skipped_files_count = 0
        self.errors_count = 0

        if not os.path.exists(self.target_path):
            logger.error(f"[USBScanner] Target path does not exist: {self.target_path}")
            return

        for root, dirs, files in os.walk(self.target_path, followlinks=False, onerror=self._on_walk_error):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                try:
                    # Verify path exists or is a symlink
                    if os.path.lexists(full_path):
                        self.scanned_files_count += 1
                        yield full_path
                    else:
                        self.skipped_files_count += 1
                except (PermissionError, OSError) as e:
                    self.skipped_files_count += 1
                    self.errors_count += 1
                    logger.debug(f"[USBScanner] Skipping inaccessible file {full_path}: {e}")

    def _on_walk_error(self, os_error: OSError) -> None:
        """
        Callback for os.walk errors (e.g. directory permission denied).
        Logs error and increments error counter without halting traversal.
        """
        self.errors_count += 1
        logger.debug(f"[USBScanner] OS error during directory traversal: {os_error}")

    def get_summary(self) -> Dict[str, int]:
        """
        Returns file scanning metrics summary.
        """
        return {
            "scanned_files_count": self.scanned_files_count,
            "skipped_files_count": self.skipped_files_count,
            "errors_count": self.errors_count,
        }


def enumerate_usb_files(target_path: str) -> Tuple[List[str], Dict[str, int]]:
    """Helper function to enumerate files from a target path."""
    scanner = USBScanner(target_path)
    files = scanner.enumerate_files()
    return files, scanner.get_summary()
