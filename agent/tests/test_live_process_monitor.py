import time
from unittest.mock import patch, MagicMock
import pytest
from collectors.live_process_monitor import ProcessMonitor


def test_process_monitor_diff():
    monitor = ProcessMonitor(interval=1.0, long_running_threshold=0.01)

    mock_procs_pass1 = {
        100: {
            "pid": 100, "ppid": 1, "name": "init", "exe_path": "/sbin/init",
            "username": "root", "cpu_percent": 0.0, "memory_percent": 0.1,
            "create_time_epoch": time.time() - 10, "duration_seconds": 10.0,
            "start_time": "2026-07-31T00:00:00Z", "started_at": "2026-07-31T00:00:00Z",
            "cmdline": "/sbin/init"
        }
    }

    # Pass 1: Initial snapshot
    with patch.object(monitor, "_get_current_process_map", return_value=mock_procs_pass1):
        diff1 = monitor.collect_and_diff()
        assert "created" in diff1
        assert "terminated" in diff1
        assert "long_running" in diff1
        assert "total_active" in diff1
        assert diff1["total_active"] == 1
        assert len(diff1["created"]) == 1

    # Pass 2: Same process snapshot (no new/terminated processes expected)
    with patch.object(monitor, "_get_current_process_map", return_value=mock_procs_pass1):
        diff2 = monitor.collect_and_diff()
        assert len(diff2["created"]) == 0
        assert len(diff2["terminated"]) == 0
        assert len(diff2["long_running"]) == 1


def test_process_monitor_start_stop():
    monitor = ProcessMonitor(interval=0.1)
    callback_mock = MagicMock()

    monitor.start_monitoring(device_id="00000000-0000-0000-0000-000000000001", callback=callback_mock)
    assert monitor._running is True
    time.sleep(0.35)
    monitor.stop_monitoring()
    assert monitor._running is False
    assert callback_mock.call_count >= 2
