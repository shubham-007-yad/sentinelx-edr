import ctypes
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from logger import logger


class FileMetadataCollector:
    """
    File Metadata Forensic Extraction Engine.
    Extracts file attributes including name, extension, full path, byte size,
    created/modified timestamps (UTC ISO 8601), and hidden file attributes.
    """

    def collect(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Extracts metadata for a specified file path.
        Returns a dictionary or None if file is inaccessible.
        """
        try:
            abs_path = os.path.abspath(file_path)
            if not os.path.lexists(abs_path):
                logger.warning(f"[FileMetadataCollector] File path does not exist: {abs_path}")
                return None

            stat_info = os.stat(abs_path)
            file_name = os.path.basename(abs_path)
            ext = os.path.splitext(file_name)[1].lower()

            # Timestamps
            created_at = self._format_timestamp(getattr(stat_info, 'st_ctime', None))
            modified_at = self._format_timestamp(getattr(stat_info, 'st_mtime', None))

            # Hidden status
            hidden_status = self.is_hidden(abs_path)

            file_size = stat_info.st_size

            return {
                "file_name": file_name,
                "extension": ext,
                "full_path": abs_path,
                "size": file_size,
                "file_size": file_size,
                "hidden": hidden_status,
                "is_hidden": hidden_status,
                "created_at": created_at,
                "modified_at": modified_at,
            }

        except (OSError, PermissionError) as e:
            logger.error(f"[FileMetadataCollector] Error extracting metadata for {file_path}: {e}")
            return None

    def is_hidden(self, file_path: str) -> bool:
        """
        Determines whether a file is hidden (dotfile on Unix or FILE_ATTRIBUTE_HIDDEN on Win32).
        """
        file_name = os.path.basename(file_path)
        if file_name.startswith('.'):
            return True

        if sys.platform == "win32":
            try:
                attrs = ctypes.windll.kernel32.GetFileAttributesW(ctypes.c_wchar_p(file_path))
                if attrs != -1:
                    FILE_ATTRIBUTE_HIDDEN = 0x2
                    return bool(attrs & FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass

        return False

    def _format_timestamp(self, ts: Optional[float]) -> Optional[str]:
        if ts is None:
            return None
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.isoformat()
        except Exception:
            return None

    def to_json(self, file_path: str, indent: int = 2) -> Optional[str]:
        """
        Collects file metadata and serializes to structured JSON string.
        """
        data = self.collect(file_path)
        if data is None:
            return None
        return json.dumps(data, indent=indent)


def collect_file_metadata(file_path: str) -> Optional[Dict[str, Any]]:
    """Helper function to collect file metadata dict."""
    return FileMetadataCollector().collect(file_path)


def get_file_metadata_json(file_path: str, indent: int = 2) -> Optional[str]:
    """Helper function to return JSON string for file metadata."""
    return FileMetadataCollector().to_json(file_path, indent=indent)
