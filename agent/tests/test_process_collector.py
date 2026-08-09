from unittest.mock import patch, MagicMock
import pytest
from collectors.process_collector import ProcessCollector, collect_process_inventory


def test_collect_process_inventory():
    collector = ProcessCollector()
    processes = collector.collect()
    assert isinstance(processes, list)
    assert len(processes) > 0

    first_proc = processes[0]
    required_keys = {"pid", "ppid", "name", "exe_path", "username", "cpu_percent", "memory_percent", "start_time", "cmdline"}
    assert required_keys.issubset(set(first_proc.keys()))
    assert isinstance(first_proc["pid"], int)


@patch("requests.post")
def test_send_processes(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_post.return_value = mock_response

    collector = ProcessCollector()
    result = collector.send_processes(backend_url="http://localhost:8000", device_id="00000000-0000-0000-0000-000000000001")
    assert result is True
    assert mock_post.called
