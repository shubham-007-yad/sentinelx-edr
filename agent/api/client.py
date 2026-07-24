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
        self.device_id: Optional[str] = self._load_device_id()

    def _load_device_id(self) -> Optional[str]:
        """Loads cached device ID if available."""
        if os.path.exists(self.device_id_file):
            try:
                with open(self.device_id_file, "r") as f:
                    device_id = f.read().strip()
                    if device_id:
                        logger.info(f"Loaded existing cached Device ID from {self.device_id_file}: {device_id}")
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
        """
        url = f"{self.backend_url}/devices/register"
        logger.info(f"POST {url}")
        try:
            response = requests.post(url, json=system_info, timeout=10)
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
