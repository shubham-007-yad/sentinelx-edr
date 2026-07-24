import json
import platform
import socket
import sys
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


def get_architecture() -> str:
    """Returns system architecture string (e.g., 64-bit, 32-bit)."""
    arch = platform.architecture()[0]
    return arch if arch else platform.machine()


class SystemInfoCollector:
    """Collector for gathering detailed endpoint system information."""

    def collect(self) -> dict:
        """
        Collects endpoint information:
        Hostname, Operating System, OS Version, Architecture, IP Address,
        MAC Address, Agent Version, Python Version.
        """
        ip = get_ip_address()
        mac = get_mac_address()
        os_name = f"{platform.system()} {platform.release()}".strip()
        os_ver = platform.version() or platform.release()
        arch = get_architecture()
        hostname = platform.node() or socket.gethostname()

        return {
            "hostname": hostname,
            "os": os_name,
            "os_type": get_os_type(),
            "os_version": os_ver,
            "architecture": arch,
            "ip": ip,
            "ip_address": ip,
            "mac": mac,
            "mac_address": mac,
            "agent_version": config.AGENT_VERSION,
            "python_version": sys.version.split()[0]
        }

    def to_json(self, indent: int = 2) -> str:
        """Returns JSON representation of system information."""
        return json.dumps(self.collect(), indent=indent)


def collect_system_info() -> dict:
    """Utility function to collect system info dictionary."""
    return SystemInfoCollector().collect()


def get_system_info_json() -> str:
    """Utility function to return formatted JSON system info string."""
    return SystemInfoCollector().to_json()
