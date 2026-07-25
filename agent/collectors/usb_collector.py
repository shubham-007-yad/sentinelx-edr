import ctypes
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from logger import logger


class USBMetadataCollector:
    """
    USB Metadata Collector.
    Gathers detailed filesystem, capacity, volume label, serial number, and timestamp information
    for connected USB devices and formats it into structured JSON payloads.
    """

    DRIVE_REMOVABLE = 2

    def collect_drive(self, drive_letter: str) -> Dict[str, Any]:
        """
        Collects comprehensive metadata for a specific drive letter (e.g., 'E:').
        """
        norm_drive = drive_letter.rstrip('\\')
        if not norm_drive.endswith(':'):
            norm_drive += ':'
        drive_path = norm_drive + '\\'

        metadata = {
            "drive_letter": norm_drive,
            "volume_label": "",
            "filesystem": "",
            "total_size": 0,
            "free_space": 0,
            "serial_number": "",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if sys.platform == "win32":
            metadata.update(self._collect_win32_drive(drive_path, norm_drive))
        else:
            metadata.update(self._collect_fallback_drive(drive_path, norm_drive))

        return metadata

    def _collect_win32_drive(self, drive_path: str, norm_drive: str) -> Dict[str, Any]:
        result = {}
        try:
            kernel32 = ctypes.windll.kernel32

            volume_name_buf = ctypes.create_unicode_buffer(261)
            file_system_buf = ctypes.create_unicode_buffer(261)
            serial_number = ctypes.c_ulong(0)
            max_component_len = ctypes.c_ulong(0)
            file_system_flags = ctypes.c_ulong(0)

            vol_success = kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive_path),
                volume_name_buf,
                ctypes.sizeof(volume_name_buf),
                ctypes.byref(serial_number),
                ctypes.byref(max_component_len),
                ctypes.byref(file_system_flags),
                file_system_buf,
                ctypes.sizeof(file_system_buf)
            )

            if vol_success:
                result["volume_label"] = volume_name_buf.value
                result["filesystem"] = file_system_buf.value
                result["serial_number"] = f"{serial_number.value:08X}" if serial_number.value else ""

            free_bytes_available = ctypes.c_ulonglong(0)
            total_number_of_bytes = ctypes.c_ulonglong(0)
            total_number_of_free_bytes = ctypes.c_ulonglong(0)

            space_success = kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(drive_path),
                ctypes.byref(free_bytes_available),
                ctypes.byref(total_number_of_bytes),
                ctypes.byref(total_number_of_free_bytes)
            )

            if space_success:
                result["total_size"] = total_number_of_bytes.value
                result["free_space"] = free_bytes_available.value

        except Exception as e:
            logger.error(f"[USBMetadataCollector] Error collecting Win32 metadata for {norm_drive}: {e}")

        return result

    def _collect_fallback_drive(self, drive_path: str, norm_drive: str) -> Dict[str, Any]:
        result = {}
        try:
            import psutil
            for part in psutil.disk_partitions(all=True):
                if norm_drive in part.mountpoint or part.mountpoint in norm_drive:
                    result["filesystem"] = part.fstype.upper()
                    result["volume_label"] = os.path.basename(part.mountpoint) or norm_drive
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        result["total_size"] = usage.total
                        result["free_space"] = usage.free
                    except Exception:
                        pass
                    break
        except Exception:
            pass
        return result

    def collect_all(self) -> List[Dict[str, Any]]:
        """
        Collects metadata payloads for all currently attached USB removable drives.
        """
        payloads: List[Dict[str, Any]] = []
        if sys.platform == "win32":
            try:
                kernel32 = ctypes.windll.kernel32
                buffer_size = 512
                buffer = ctypes.create_unicode_buffer(buffer_size)
                length = kernel32.GetLogicalDriveStringsW(buffer_size, buffer)
                if length:
                    drives = buffer.raw[: length * 2].decode('utf-16-le').split('\x00')
                    for d in drives:
                        if d and kernel32.GetDriveTypeW(ctypes.c_wchar_p(d)) == self.DRIVE_REMOVABLE:
                            payloads.append(self.collect_drive(d))
            except Exception as e:
                logger.error(f"[USBMetadataCollector] Error scanning logical drives: {e}")
        else:
            try:
                import psutil
                for part in psutil.disk_partitions(all=True):
                    if 'removable' in part.opts.lower() or part.fstype.lower() in ('fat32', 'exfat', 'vfat', 'msdos'):
                        payloads.append(self.collect_drive(part.mountpoint))
            except Exception:
                pass
        return payloads

    def to_json(self, drive_letter: Optional[str] = None, indent: int = 2) -> str:
        """
        Returns structured JSON payload string for a single drive (if drive_letter specified)
        or all connected USB drives.
        """
        if drive_letter:
            data = self.collect_drive(drive_letter)
        else:
            data = self.collect_all()
        return json.dumps(data, indent=indent)


def collect_usb_metadata(drive_letter: Optional[str] = None) -> Any:
    """Helper function to collect USB metadata dict/list."""
    collector = USBMetadataCollector()
    if drive_letter:
        return collector.collect_drive(drive_letter)
    return collector.collect_all()


def get_usb_metadata_json(drive_letter: Optional[str] = None, indent: int = 2) -> str:
    """Helper function to return structured JSON payload string."""
    return USBMetadataCollector().to_json(drive_letter=drive_letter, indent=indent)
