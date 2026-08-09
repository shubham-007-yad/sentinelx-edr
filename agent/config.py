import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file if present
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

def harden_file_permissions(file_path: str):
    """Enforces strict local file permissions (0600) on sensitive configuration/identity files."""
    if os.path.exists(file_path):
        try:
            os.chmod(file_path, 0o600)
        except Exception:
            pass

class Config:
    """Agent Configuration Settings"""
    ENVIRONMENT: str = os.getenv("SENTINELX_ENVIRONMENT", "production").lower()
    BACKEND_URL: str = os.getenv("SENTINELX_BACKEND_URL", "https://localhost/api/v1").rstrip("/")
    HEARTBEAT_INTERVAL: int = int(os.getenv("SENTINELX_HEARTBEAT_INTERVAL", "10"))
    LOG_LEVEL: str = os.getenv("SENTINELX_LOG_LEVEL", "INFO").upper()
    AGENT_VERSION: str = os.getenv("SENTINELX_AGENT_VERSION", "1.0.0")
    DEVICE_CACHE_FILE: str = os.getenv("SENTINELX_DEVICE_CACHE_FILE", ".device_id")
    VERIFY_TLS: bool = os.getenv("SENTINELX_VERIFY_TLS", "true").lower() in ("true", "1", "t")

    @classmethod
    def display(cls) -> dict:
        return {
            "ENVIRONMENT": cls.ENVIRONMENT,
            "BACKEND_URL": cls.BACKEND_URL,
            "HEARTBEAT_INTERVAL": cls.HEARTBEAT_INTERVAL,
            "LOG_LEVEL": cls.LOG_LEVEL,
            "AGENT_VERSION": cls.AGENT_VERSION,
            "DEVICE_CACHE_FILE": cls.DEVICE_CACHE_FILE,
            "VERIFY_TLS": cls.VERIFY_TLS
        }

config = Config()

# Harden local file permissions on startup
harden_file_permissions(str(env_path))
harden_file_permissions(config.DEVICE_CACHE_FILE)
