import os
import json
import threading
from typing import List, Dict, Any, Optional
from logger import logger

BUFFER_FILE_PATH = os.environ.get("SENTINELX_TELEMETRY_BUFFER", ".telemetry_buffer.json")
MAX_BUFFERED_ITEMS = 5000  # Cap maximum offline events to prevent unlimited disk usage


class LocalTelemetryBuffer:
    """
    Manages offline local buffering of telemetry events during network outages.
    Ensures no telemetry data is lost when backend is unreachable.
    Flushes buffered items automatically when backend connectivity is restored.
    """

    def __init__(self, buffer_file: str = None):
        self.buffer_file = buffer_file or BUFFER_FILE_PATH
        self._lock = threading.Lock()
        self._harden_permissions()

    def _harden_permissions(self):
        """Restricts local file permissions to 0600."""
        if os.path.exists(self.buffer_file):
            try:
                os.chmod(self.buffer_file, 0o600)
            except Exception:
                pass

    def enqueue(self, event_data: Dict[str, Any]):
        """Appends a telemetry event to local offline buffer disk file."""
        with self._lock:
            items = self._read_items()
            if len(items) >= MAX_BUFFERED_ITEMS:
                # FIFO drop oldest if buffer limit exceeded
                items.pop(0)
            items.append(event_data)
            self._write_items(items)
            logger.info(f"[TelemetryBuffer] Buffered event offline. Total queued: {len(items)}")

    def peek_batch(self, batch_size: int = 100) -> List[Dict[str, Any]]:
        """Returns the next batch of buffered events without removing them."""
        with self._lock:
            items = self._read_items()
            return items[:batch_size]

    def remove_batch(self, count: int):
        """Removes successfully flushed events from the offline buffer."""
        with self._lock:
            items = self._read_items()
            remaining = items[count:]
            self._write_items(remaining)
            logger.info(f"[TelemetryBuffer] Flushed {count} events. Remaining in buffer: {len(remaining)}")

    def count(self) -> int:
        with self._lock:
            return len(self._read_items())

    def _read_items(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.buffer_file):
            return []
        try:
            with open(self.buffer_file, "r") as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)
        except Exception as e:
            logger.warning(f"[TelemetryBuffer] Could not read buffer file: {e}")
            return []

    def _write_items(self, items: List[Dict[str, Any]]):
        try:
            with open(self.buffer_file, "w") as f:
                json.dump(items, f)
            self._harden_permissions()
        except Exception as e:
            logger.error(f"[TelemetryBuffer] Failed to write buffer file: {e}")


telemetry_buffer = LocalTelemetryBuffer()


def flush_offline_telemetry(api_client, buffer_instance: Optional[LocalTelemetryBuffer] = None, batch_size: int = 100) -> int:
    """
    Attempts to flush queued offline telemetry items to backend /telemetry/ingest endpoint.
    Returns count of successfully uploaded events.
    """
    target_buffer = buffer_instance or telemetry_buffer
    total_count = target_buffer.count()
    if total_count == 0:
        return 0

    logger.info(f"[TelemetryBuffer] Attempting to flush {total_count} offline telemetry events to backend...")
    flushed_total = 0

    while target_buffer.count() > 0:
        batch = target_buffer.peek_batch(batch_size)
        if not batch:
            break

        url = f"{api_client.backend_url}/telemetry/ingest"
        payload = {
            "device_id": api_client.device_id or "offline_device",
            "events": batch
        }

        try:
            res = api_client.session.post(url, json=payload, timeout=10)
            if res.status_code in (200, 201):
                target_buffer.remove_batch(len(batch))
                flushed_total += len(batch)
            else:
                logger.warning(f"[TelemetryBuffer] Backend returned HTTP {res.status_code} during flush. Halting flush cycle.")
                break
        except Exception as e:
            logger.warning(f"[TelemetryBuffer] Network error during flush: {e}. Backend remains unreachable.")
            break

    return flushed_total
