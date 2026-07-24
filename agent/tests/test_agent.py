import json
from config import config
from collectors import SystemInfoCollector, collect_system_info, get_system_info_json
from api import APIClient


def test_config_loading():
    assert config.BACKEND_URL is not None
    assert config.AGENT_VERSION == "1.0.0"
    assert config.HEARTBEAT_INTERVAL > 0
    display_dict = config.display()
    assert "BACKEND_URL" in display_dict
    assert "AGENT_VERSION" in display_dict


def test_sys_info_collector_fields():
    info = collect_system_info()
    required_keys = [
        "hostname", "os", "os_type", "os_version", "architecture",
        "ip", "ip_address", "mac", "mac_address", "agent_version", "python_version"
    ]
    for key in required_keys:
        assert key in info and info[key] is not None

    assert info["os_type"] in ["WINDOWS", "LINUX", "MACOS", "OTHER"]
    assert info["agent_version"] == "1.0.0"


def test_sys_info_json_formatting():
    json_str = get_system_info_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["hostname"] is not None
    assert "os" in parsed
    assert "architecture" in parsed
    assert "ip" in parsed
    assert "mac" in parsed
    assert "python_version" in parsed


def test_api_client_initialization(tmp_path):
    cache_file = str(tmp_path / ".device_id_test")
    config.DEVICE_CACHE_FILE = cache_file

    client = APIClient(backend_url="http://testbackend/api/v1")
    assert client.backend_url == "http://testbackend/api/v1"
    assert client.device_id is None
