from config import config
from collectors import collect_system_info
from api import APIClient


def test_config_loading():
    assert config.BACKEND_URL is not None
    assert config.AGENT_VERSION == "1.0.0"
    assert config.HEARTBEAT_INTERVAL > 0
    display_dict = config.display()
    assert "BACKEND_URL" in display_dict
    assert "AGENT_VERSION" in display_dict


def test_sys_info_collector():
    info = collect_system_info()
    assert "hostname" in info and info["hostname"]
    assert "ip_address" in info and info["ip_address"]
    assert "mac_address" in info and info["mac_address"]
    assert "os_type" in info and info["os_type"] in ["WINDOWS", "LINUX", "MACOS", "OTHER"]
    assert "os_version" in info and info["os_version"]
    assert info["agent_version"] == "1.0.0"


def test_api_client_initialization(tmp_path):
    cache_file = str(tmp_path / ".device_id_test")
    config.DEVICE_CACHE_FILE = cache_file

    client = APIClient(backend_url="http://testbackend/api/v1")
    assert client.backend_url == "http://testbackend/api/v1"
    assert client.device_id is None
