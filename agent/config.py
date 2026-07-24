import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file if present
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)


class Config:
    """Agent Configuration Settings"""
    BACKEND_URL: str = os.getenv("SENTINELX_BACKEND_URL", "http://localhost:8000/api/v1").rstrip("/")
    HEARTBEAT_INTERVAL: int = int(os.getenv("SENTINELX_HEARTBEAT_INTERVAL", "10"))
    LOG_LEVEL: str = os.getenv("SENTINELX_LOG_LEVEL", "INFO").upper()
    AGENT_VERSION: str = os.getenv("SENTINELX_AGENT_VERSION", "1.0.0")
    DEVICE_CACHE_FILE: str = os.getenv("SENTINELX_DEVICE_CACHE_FILE", ".device_id")

    @classmethod
    def display(cls) -> dict:
        return {
            "BACKEND_URL": cls.BACKEND_URL,
            "HEARTBEAT_INTERVAL": cls.HEARTBEAT_INTERVAL,
            "LOG_LEVEL": cls.LOG_LEVEL,
            "AGENT_VERSION": cls.AGENT_VERSION,
            "DEVICE_CACHE_FILE": cls.DEVICE_CACHE_FILE,
        }


config = Config()
