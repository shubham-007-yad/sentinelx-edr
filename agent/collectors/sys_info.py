import platform
import socket
import uuid
from config import config


def get_mac_address() -> str:
    """Returns standard MAC address string (XX:XX:XX:XX:XX:XX)."""
    mac = uuid.getnode()
    mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    return mac_str


def get_ip_address() -> str:
    """Attempts to retrieve active outbound local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def get_os_type() -> str:
    """Returns normalized OS type (WINDOWS, LINUX, MACOS, OTHER)."""
    sys_name = platform.system().upper()
    if "DARWIN" in sys_name or "MAC" in sys_name:
        return "MACOS"
    if "WIN" in sys_name:
        return "WINDOWS"
    if "LINUX" in sys_name:
        return "LINUX"
    return "OTHER"


def collect_system_info() -> dict:
    """Collects system details for agent registration and heartbeats."""
    return {
        "hostname": platform.node() or socket.gethostname(),
        "ip_address": get_ip_address(),
        "mac_address": get_mac_address(),
        "os_type": get_os_type(),
        "os_version": f"{platform.system()} {platform.release()}",
        "agent_version": config.AGENT_VERSION
    }
