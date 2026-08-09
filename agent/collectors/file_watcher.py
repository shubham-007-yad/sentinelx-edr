import os
import sys
import time
import queue
import hashlib
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable, Set

from logger import logger

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    FileSystemEventHandler = object


def _safe_calculate_sha256(file_path: str) -> str:
    try:
        if not os.path.isfile(file_path):
            return ""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception:
        return ""


def get_default_monitored_directories() -> List[str]:
    home = os.path.expanduser("~")
    directories = []

    if sys.platform == "win32":
        directories = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Documents"),
            os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        ]
    else:
        directories = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Documents"),
        ]

    valid_dirs = []
    for d in directories:
        abs_d = os.path.abspath(d)
        if os.path.exists(abs_d) and os.path.isdir(abs_d):
            valid_dirs.append(abs_d)

    return valid_dirs


class FileWatcherEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler for normalizing real-time filesystem events.
    """

    def __init__(self, event_callback: Callable[[Dict[str, Any]], None], debounce_seconds: float = 0.1):
        super().__init__()
        self.event_callback = event_callback
        self.debounce_seconds = debounce_seconds
        self._last_event_time: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _should_debounce(self, key: str) -> bool:
        if self.debounce_seconds <= 0:
            return False
        now = time.time()
        with self._lock:
            last = self._last_event_time.get(key, 0)
            if now - last < self.debounce_seconds:
                return True
            self._last_event_time[key] = now
            return False

    def on_any_event(self, event):
        if event.is_directory:
            return

        src_path = os.path.abspath(event.src_path)
        evt_type = str(event.event_type).upper()

        if evt_type in ["MOVED", "RENAMED"]:
            dest_path = os.path.abspath(getattr(event, 'dest_path', src_path))
            if self._should_debounce(f"RENAMED:{dest_path}"):
                return
            payload = self._build_event_payload("RENAMED", dest_path, old_path=src_path)
            if payload:
                self.event_callback(payload)
        elif evt_type == "DELETED":
            if self._should_debounce(f"DELETED:{src_path}"):
                return
            payload = {
                "event_type": "DELETED",
                "file_path": src_path,
                "file_name": os.path.basename(src_path),
                "old_path": None,
                "sha256": "",
                "size": 0,
                "is_executable": False,
                "last_modified": datetime.now(timezone.utc).isoformat(),
                "owner": None,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.event_callback(payload)
        elif evt_type in ["CREATED", "MODIFIED"]:
            if self._should_debounce(f"{evt_type}:{src_path}"):
                return
            payload = self._build_event_payload(evt_type, src_path)
            if payload:
                self.event_callback(payload)

    def _build_event_payload(self, event_type: str, file_path: str, old_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            if not os.path.exists(file_path):
                return None

            stat_info = os.stat(file_path)
            file_name = os.path.basename(file_path)
            file_size = stat_info.st_size
            sha256_hash = _safe_calculate_sha256(file_path) if file_size < 100 * 1024 * 1024 else ""

            is_exec = False
            if sys.platform != "win32":
                is_exec = bool(stat_info.st_mode & 0o111)
            else:
                ext = os.path.splitext(file_name)[1].lower()
                is_exec = ext in ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.msi']

            owner = None
            try:
                import pwd
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
            except Exception:
                pass

            last_mod = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc).isoformat()

            return {
                "event_type": event_type,
                "file_path": file_path,
                "file_name": file_name,
                "old_path": old_path,
                "sha256": sha256_hash or "",
                "size": file_size,
                "is_executable": is_exec,
                "last_modified": last_mod,
                "owner": owner,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.debug(f"[FileWatcher] Could not build payload for {file_path}: {e}")
            return None


class RealTimeFileMonitor:
    """
    Real-Time File Monitoring Service for Day 11 FIM.
    Monitors target folders using watchdog + directory poller engine.
    """

    def __init__(self, watch_dirs: Optional[List[str]] = None, callback: Optional[Callable[[Dict[str, Any]], None]] = None, debounce_seconds: float = 0.1, poll_interval: float = 0.2):
        self.watch_dirs = watch_dirs if watch_dirs is not None else get_default_monitored_directories()
        self.callback = callback
        self.debounce_seconds = debounce_seconds
        self.poll_interval = poll_interval
        self.event_queue: queue.Queue = queue.Queue()
        self._observer: Optional[Any] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._running = False
        self._snapshot: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._seen_events: Set[str] = set()

    def add_directory(self, path: str):
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path) and os.path.isdir(abs_path) and abs_path not in self.watch_dirs:
            self.watch_dirs.append(abs_path)

    def _on_event(self, event_data: Dict[str, Any]):
        event_key = f"{event_data['event_type']}:{event_data['file_path']}:{event_data.get('size', 0)}:{event_data.get('sha256', '')}"
        with self._lock:
            if event_key in self._seen_events:
                return
            self._seen_events.add(event_key)
            if len(self._seen_events) > 500:
                self._seen_events.clear()

        self.event_queue.put(event_data)
        logger.info(f"[FIM Monitor] Event {event_data['event_type']}: {event_data['file_path']}")
        if self.callback:
            try:
                self.callback(event_data)
            except Exception as e:
                logger.error(f"[FIM Monitor] Error in event callback: {e}")

    def _scan_snapshot(self) -> Dict[str, Dict[str, Any]]:
        curr: Dict[str, Dict[str, Any]] = {}
        for d in self.watch_dirs:
            if not os.path.exists(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    file_path = os.path.abspath(os.path.join(root, f))
                    try:
                        st = os.stat(file_path)
                        curr[file_path] = {
                            "mtime": st.st_mtime,
                            "size": st.st_size,
                            "is_exec": bool(st.st_mode & 0o111) if sys.platform != "win32" else os.path.splitext(f)[1].lower() in ['.exe', '.bat', '.cmd', '.ps1', '.vbs']
                        }
                    except (OSError, PermissionError):
                        continue
        return curr

    def _poller_loop(self):
        self._snapshot = self._scan_snapshot()
        while self._running:
            time.sleep(self.poll_interval)
            current_snap = self._scan_snapshot()

            # Check created and modified
            for path, meta in current_snap.items():
                if path not in self._snapshot:
                    file_name = os.path.basename(path)
                    sha256_hash = _safe_calculate_sha256(path) if meta["size"] < 100 * 1024 * 1024 else ""
                    self._on_event({
                        "event_type": "CREATED",
                        "file_path": path,
                        "file_name": file_name,
                        "old_path": None,
                        "sha256": sha256_hash or "",
                        "size": meta["size"],
                        "is_executable": meta["is_exec"],
                        "last_modified": datetime.fromtimestamp(meta["mtime"], tz=timezone.utc).isoformat(),
                        "owner": None,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                elif meta["mtime"] != self._snapshot[path]["mtime"] or meta["size"] != self._snapshot[path]["size"]:
                    file_name = os.path.basename(path)
                    sha256_hash = _safe_calculate_sha256(path) if meta["size"] < 100 * 1024 * 1024 else ""
                    self._on_event({
                        "event_type": "MODIFIED",
                        "file_path": path,
                        "file_name": file_name,
                        "old_path": None,
                        "sha256": sha256_hash or "",
                        "size": meta["size"],
                        "is_executable": meta["is_exec"],
                        "last_modified": datetime.fromtimestamp(meta["mtime"], tz=timezone.utc).isoformat(),
                        "owner": None,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

            # Check deleted
            for old_path in list(self._snapshot.keys()):
                if old_path not in current_snap:
                    self._on_event({
                        "event_type": "DELETED",
                        "file_path": old_path,
                        "file_name": os.path.basename(old_path),
                        "old_path": None,
                        "sha256": "",
                        "size": 0,
                        "is_executable": False,
                        "last_modified": datetime.now(timezone.utc).isoformat(),
                        "owner": None,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

            self._snapshot = current_snap

    def start(self):
        with self._lock:
            if self._running:
                return

            self._running = True

            if HAS_WATCHDOG:
                try:
                    self._observer = Observer()
                    handler = FileWatcherEventHandler(event_callback=self._on_event, debounce_seconds=self.debounce_seconds)
                    for d in self.watch_dirs:
                        if os.path.exists(d):
                            self._observer.schedule(handler, path=d, recursive=True)
                    self._observer.start()
                except Exception as e:
                    logger.warning(f"[FIM Monitor] Watchdog start warning: {e}")

            self._poll_thread = threading.Thread(target=self._poller_loop, daemon=True)
            self._poll_thread.start()
            logger.info("[FIM Monitor] Real-time file monitor and directory poller started.")

    def stop(self):
        with self._lock:
            if not self._running:
                return

            self._running = False
            if self._observer:
                try:
                    self._observer.stop()
                    self._observer.join()
                except Exception:
                    pass
                self._observer = None

            self._poll_thread = None
            logger.info("[FIM Monitor] Real-time file watcher stopped.")

    def get_events(self, max_items: int = 100) -> List[Dict[str, Any]]:
        events = []
        while not self.event_queue.empty() and len(events) < max_items:
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return events
