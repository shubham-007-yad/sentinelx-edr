import logging
import threading
import time
from typing import Dict, Any, Optional, Callable, List
import requests

logger = logging.getLogger("SentinelXAgent.PolicySyncManager")


class PolicySyncManager:
    """
    Automated Policy Distribution & Sync Daemon for SentinelX Endpoint Agent.
    Periodically queries `GET /api/v1/policies/latest` (e.g. every 10-30s),
    validates the policy version, and applies dynamic updates to all registered
    agent collector/engine modules without requiring restarts or code changes.
    """

    def __init__(
        self,
        backend_url: str,
        device_id: Optional[str] = None,
        poll_interval: float = 10.0
    ):
        self.backend_url = backend_url.rstrip('/')
        self.device_id = device_id
        self.poll_interval = poll_interval
        self.current_version: int = -1
        self.last_sync_timestamp: Optional[str] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.update_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Registers a subscriber callback to receive downloaded policy payloads."""
        self.update_callbacks.append(callback)

    def start(self):
        """Starts periodic policy synchronization worker thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._thread.start()
        logger.info(f"🔄 [PolicySyncManager] Started policy sync thread (interval: {self.poll_interval}s).")

    def stop(self):
        """Stops policy synchronization worker thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("🛑 [PolicySyncManager] Policy sync thread stopped.")

    def fetch_latest_policy(self) -> Optional[Dict[str, Any]]:
        """
        Polls `/api/v1/policies/latest` from central FastAPI backend.
        """
        url = f"{self.backend_url}/api/v1/policies/latest"
        params = {}
        if self.device_id:
            params["device_id"] = self.device_id
        if self.current_version >= 0:
            params["applied_version"] = self.current_version


        try:
            resp = requests.get(url, params=params, timeout=5)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning(f"[PolicySyncManager] Failed to fetch policy: HTTP {resp.status_code}")
                return None
        except Exception as e:
            logger.error(f"[PolicySyncManager] Error fetching policy updates: {e}")
            return None

    def sync_once(self) -> bool:
        """
        Performs a single policy fetch, version check, and callback distribution cycle.
        """
        policy_data = self.fetch_latest_policy()
        if not policy_data:
            return False

        version = policy_data.get("version", 0)

        if version > self.current_version:
            logger.info(f"✨ [Policy Sync] New policy update detected: v{version} (previous: v{self.current_version}). Applying changes...")
            self.current_version = version
            self.last_sync_timestamp = policy_data.get("timestamp")

            for callback in self.update_callbacks:
                try:
                    callback(policy_data)
                except Exception as cb_err:
                    logger.error(f"[PolicySyncManager] Error in subscriber callback: {cb_err}")

            return True

        logger.debug(f"[PolicySyncManager] Current policy v{self.current_version} is up to date.")
        return False

    def _sync_loop(self):
        while self._running:
            try:
                self.sync_once()
            except Exception as e:
                logger.error(f"[PolicySyncManager] Unhandled exception in sync loop: {e}")

            time.sleep(self.poll_interval)
