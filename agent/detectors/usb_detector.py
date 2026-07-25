import ctypes
import os
import sys
import time
import threading
from datetime import datetime, timezone
from typing import Dict, List, Callable, Optional
from dataclasses import dataclass, field
from logger import logger


@dataclass
class USBDeviceDetails:
    drive_letter: str
    volume_label: str = ""
    filesystem: str = ""
    total_size: int = 0
    free_space: int = 0
    serial_number: str = ""


@dataclass
class USBEventData:
    event_type: str  # "INSERT" or "REMOVE"
    drive_letter: str
    volume_label: str = ""
    filesystem: str = ""
    total_size: int = 0
    free_space: int = 0
    serial_number: str = ""
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "drive_letter": self.drive_letter,
            "volume_label": self.volume_label,
            "filesystem": self.filesystem,
            "total_size": self.total_size,
            "free_space": self.free_space,
            "serial_number": self.serial_number,
            "detected_at": self.detected_at,
        }


class USBEventListener:
    """Event listener manager for USB insert/remove events."""

    def __init__(self):
        self._callbacks: List[Callable[[USBEventData], None]] = []

    def register_callback(self, callback: Callable[[USBEventData], None]) -> None:
        """Register a callback function to be called when USB events occur."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable[[USBEventData], None]) -> None:
        """Unregister an existing callback function."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def emit(self, event: USBEventData) -> None:
        """Broadcast USB event to all registered listener callbacks."""
        logger.info(f"[USBEventListener] Emitting USB event: {event.event_type} - {event.drive_letter} ({event.volume_label})")
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"[USBEventListener] Callback execution failed: {e}")


class BaseUSBDetector:
    """Abstract base class for platform-specific USB detectors."""

    def get_connected_usb_drives(self) -> Dict[str, USBDeviceDetails]:
        """Returns a dict of connected USB drives keyed by drive_letter."""
        raise NotImplementedError("Platform-specific USB detector must implement get_connected_usb_drives")


class WindowsUSBDetector(BaseUSBDetector):
    """
    Windows-native USB Detector.
    Uses Win32 APIs (GetLogicalDriveStringsW, GetDriveTypeW, GetVolumeInformationW, GetDiskFreeSpaceExW)
    to query removable USB drives.
    """

    DRIVE_REMOVABLE = 2

    def get_connected_usb_drives(self) -> Dict[str, USBDeviceDetails]:
        drives: Dict[str, USBDeviceDetails] = {}

        if sys.platform != "win32":
            # Fallback for non-windows platform in dev/test environment
            return self._fallback_get_connected_drives()

        try:
            # 1. Get logical drive strings
            kernel32 = ctypes.windll.kernel32
            buffer_size = 512
            buffer = ctypes.create_unicode_buffer(buffer_size)
            length = kernel32.GetLogicalDriveStringsW(buffer_size, buffer)

            if not length:
                return drives

            drive_strings = buffer.raw[: length * 2].decode('utf-16-le').split('\x00')
            drive_strings = [d for d in drive_strings if d]

            for drive in drive_strings:
                # 2. Check if drive type is DRIVE_REMOVABLE (2)
                drive_type = kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))
                if drive_type == self.DRIVE_REMOVABLE:
                    details = self._get_win32_drive_details(drive)
                    drives[details.drive_letter] = details

        except Exception as e:
            logger.error(f"[WindowsUSBDetector] Error scanning USB drives: {e}")

        return drives

    def _get_win32_drive_details(self, drive_path: str) -> USBDeviceDetails:
        kernel32 = ctypes.windll.kernel32

        # Volume information buffers
        volume_name_buf = ctypes.create_unicode_buffer(261)
        file_system_buf = ctypes.create_unicode_buffer(261)
        serial_number = ctypes.c_ulong(0)
        max_component_len = ctypes.c_ulong(0)
        file_system_flags = ctypes.c_ulong(0)

        drive_letter = drive_path.rstrip('\\')  # e.g., "E:"

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

        volume_label = volume_name_buf.value if vol_success else ""
        filesystem = file_system_buf.value if vol_success else ""
        sn_hex = f"{serial_number.value:08X}" if vol_success and serial_number.value else ""

        # Free space buffers
        free_bytes_available = ctypes.c_ulonglong(0)
        total_number_of_bytes = ctypes.c_ulonglong(0)
        total_number_of_free_bytes = ctypes.c_ulonglong(0)

        space_success = kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(drive_path),
            ctypes.byref(free_bytes_available),
            ctypes.byref(total_number_of_bytes),
            ctypes.byref(total_number_of_free_bytes)
        )

        total_size = total_number_of_bytes.value if space_success else 0
        free_space = free_bytes_available.value if space_success else 0

        return USBDeviceDetails(
            drive_letter=drive_letter,
            volume_label=volume_label,
            filesystem=filesystem,
            total_size=total_size,
            free_space=free_space,
            serial_number=sn_hex
        )

    def _fallback_get_connected_drives(self) -> Dict[str, USBDeviceDetails]:
        """Fallback method for dev/test execution on non-Windows platforms."""
        drives: Dict[str, USBDeviceDetails] = {}
        try:
            import psutil
            for part in psutil.disk_partitions(all=True):
                if 'removable' in part.opts.lower() or part.fstype.lower() in ('fat32', 'exfat', 'vfat', 'msdos'):
                    drive_letter = part.mountpoint
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        total_size = usage.total
                        free_space = usage.free
                    except Exception:
                        total_size = 0
                        free_space = 0

                    drives[drive_letter] = USBDeviceDetails(
                        drive_letter=drive_letter,
                        volume_label=os.path.basename(part.mountpoint) or drive_letter,
                        filesystem=part.fstype.upper(),
                        total_size=total_size,
                        free_space=free_space
                    )
        except Exception:
            pass
        return drives


class MockUSBDetector(BaseUSBDetector):
    """Mock USB Detector for unit testing drive insertions and removals."""

    def __init__(self):
        self._drives: Dict[str, USBDeviceDetails] = {}

    def set_connected_drives(self, drives: Dict[str, USBDeviceDetails]):
        self._drives = dict(drives)

    def plug_in(self, device: USBDeviceDetails):
        self._drives[device.drive_letter] = device

    def unplug(self, drive_letter: str):
        self._drives.pop(drive_letter, None)

    def get_connected_usb_drives(self) -> Dict[str, USBDeviceDetails]:
        return dict(self._drives)


class USBDetectorService:
    """
    USB Detector Service.
    Monitors USB device connections/disconnections by polling connected drive snapshots
    and triggering event listener callbacks for INSERT and REMOVE events.
    """

    def __init__(self, detector: Optional[BaseUSBDetector] = None):
        if detector is not None:
            self.detector = detector
        else:
            self.detector = WindowsUSBDetector()

        self.event_listener = USBEventListener()
        self.previous_drives: Dict[str, USBDeviceDetails] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def scan_and_detect(self) -> List[USBEventData]:
        """
        Scans current connected USB drives, compares against previous snapshot,
        emits INSERT / REMOVE events via event_listener, and updates state.
        Returns list of newly detected USBEventData.
        """
        current_drives = self.detector.get_connected_usb_drives()
        events: List[USBEventData] = []

        # Detect INSERT events (drives present now, but not in previous snapshot)
        for drive_letter, details in current_drives.items():
            if drive_letter not in self.previous_drives:
                event = USBEventData(
                    event_type="INSERT",
                    drive_letter=details.drive_letter,
                    volume_label=details.volume_label,
                    filesystem=details.filesystem,
                    total_size=details.total_size,
                    free_space=details.free_space,
                    serial_number=details.serial_number
                )
                events.append(event)
                self.event_listener.emit(event)

        # Detect REMOVE events (drives in previous snapshot, but missing now)
        for drive_letter, details in list(self.previous_drives.items()):
            if drive_letter not in current_drives:
                event = USBEventData(
                    event_type="REMOVE",
                    drive_letter=details.drive_letter,
                    volume_label=details.volume_label,
                    filesystem=details.filesystem,
                    total_size=details.total_size,
                    free_space=details.free_space,
                    serial_number=details.serial_number
                )
                events.append(event)
                self.event_listener.emit(event)

        self.previous_drives = current_drives
        return events

    def start_monitoring(self, interval: float = 2.0) -> None:
        """Starts background monitoring loop in a separate thread."""
        if self._running:
            return

        self._running = True
        # Initial scan to set baseline state
        self.previous_drives = self.detector.get_connected_usb_drives()

        def _monitor_loop():
            logger.info(f"[USBDetectorService] Started USB monitoring worker thread (Interval: {interval}s).")
            while self._running:
                try:
                    self.scan_and_detect()
                except Exception as e:
                    logger.error(f"[USBDetectorService] Error during detection loop: {e}")
                time.sleep(interval)
            logger.info("[USBDetectorService] USB monitoring worker thread stopped.")

        self._thread = threading.Thread(target=_monitor_loop, daemon=True)
        self._thread.start()

    def stop_monitoring(self) -> None:
        """Stops background monitoring loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
            self._thread = None
