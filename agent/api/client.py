import os
from typing import Optional
import requests
from config import config
from logger import logger


class APIClient:
    """Client for communicating with the SentinelX EDR Backend API."""

    def __init__(self, backend_url: Optional[str] = None):
        self.backend_url = (backend_url or config.BACKEND_URL).rstrip("/")
        self.device_id_file = config.DEVICE_CACHE_FILE
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": f"SentinelX-Agent/{config.AGENT_VERSION}",
            "Accept": "application/json"
        })
        self.device_id: Optional[str] = self._load_device_id()

    def _load_device_id(self) -> Optional[str]:
        """Loads cached device ID if available."""
        if os.path.exists(self.device_id_file):
            try:
                with open(self.device_id_file, "r") as f:
                    device_id = f.read().strip()
                    if device_id:
                        return device_id
            except Exception as e:
                logger.warning(f"Could not read device cache file: {e}")
        return None

    def _save_device_id(self, device_id: str) -> None:
        """Caches device ID locally."""
        try:
            with open(self.device_id_file, "w") as f:
                f.write(device_id)
            self.device_id = device_id
            logger.info(f"Saved device_id locally to cache file: {self.device_id_file}")
        except Exception as e:
            logger.warning(f"Could not save device cache file: {e}")

    def register_device(self, system_info: dict) -> Optional[dict]:
        """
        Flow:
        POST /devices/register -> Receive device_id -> Save locally
        Reuses persistent HTTP session connection pool for efficiency.
        """
        url = f"{self.backend_url}/devices/register"
        logger.info(f"POST {url}")
        try:
            response = self.session.post(url, json=system_info, timeout=10)
            logger.info(f"Registration Response Received (HTTP {response.status_code})")

            if response.status_code in (200, 201):
                data = response.json()
                device_id = data.get("id") or data.get("device_id")
                if device_id:
                    logger.info(f"Received device_id: {device_id}")
                    self._save_device_id(str(device_id))
                    logger.info(f"Endpoint successfully registered with backend database!")
                return data
            else:
                logger.error(f"Registration failed with HTTP {response.status_code}: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error connecting to backend at {url}: {e}")
            return None

    def send_heartbeat(self, ip_address: Optional[str] = None) -> Optional[dict]:
        """
        Flow:
        Every interval -> POST /devices/heartbeat -> Update last_seen timestamp
        Reuses persistent HTTP keep-alive session to eliminate connection overhead.
        """
        if not self.device_id:
            self.device_id = self._load_device_id()

        if not self.device_id:
            logger.warning("Cannot send heartbeat: No cached device_id found. Registering endpoint first.")
            return None

        url = f"{self.backend_url}/devices/heartbeat"
        payload = {
            "device_id": self.device_id,
            "status": "ONLINE"
        }
        if ip_address:
            payload["ip_address"] = ip_address

        logger.info(f"POST {url} (device_id: {self.device_id})")
        try:
            response = self.session.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Heartbeat acknowledged! updated last_seen: {data.get('last_seen')}")
                return data
            else:
                logger.error(f"Heartbeat failed with HTTP {response.status_code}: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error sending heartbeat to {url}: {e}")
            return None

    def close(self):
        """Closes the underlying HTTP session."""
        self.session.close()
