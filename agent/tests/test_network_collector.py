import pytest
from unittest.mock import patch, MagicMock
from collectors.network_collector import NetworkCollector, NetworkMonitor, collect_network_connections


def test_network_collector_collect():
    collector = NetworkCollector()

    mock_laddr = MagicMock()
    mock_laddr.ip = "127.0.0.1"
    mock_laddr.port = 8080

    mock_raddr = MagicMock()
    mock_raddr.ip = "1.2.3.4"
    mock_raddr.port = 443

    mock_conn = MagicMock()
    mock_conn.pid = 100
    mock_conn.laddr = mock_laddr
    mock_conn.raddr = mock_raddr
    mock_conn.type = 1  # SOCK_STREAM
    mock_conn.status = "ESTABLISHED"

    mock_proc = MagicMock()
    mock_proc.name.return_value = "test_app"
    mock_proc.exe.return_value = "/usr/bin/test_app"

    with patch("psutil.net_connections", return_value=[mock_conn]), \
         patch("psutil.Process", return_value=mock_proc):
        connections = collector.collect()
        assert len(connections) == 1
        conn = connections[0]
        assert conn["pid"] == 100
        assert conn["process_name"] == "test_app"
        assert conn["executable_path"] == "/usr/bin/test_app"
        assert conn["local_ip"] == "127.0.0.1"
        assert conn["local_port"] == 8080
        assert conn["remote_ip"] == "1.2.3.4"
        assert conn["remote_port"] == 443
        assert conn["protocol"] == "TCP"
        assert conn["state"] == "ESTABLISHED"


def test_network_collector_send_payload():
    collector = NetworkCollector()
    dummy_conns = [{
        "pid": 100,
        "process_name": "test_app",
        "executable_path": "/usr/bin/test_app",
        "local_ip": "127.0.0.1",
        "local_port": 8080,
        "remote_ip": "1.2.3.4",
        "remote_port": 443,
        "protocol": "TCP",
        "state": "ESTABLISHED",
        "bytes_sent": 0,
        "bytes_received": 0,
        "timestamp": "2026-07-31T12:00:00Z"
    }]

    with patch.object(collector, "collect", return_value=dummy_conns), \
         patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 201
        success = collector.send_network_connections("http://localhost:8000", "device-uuid-123")
        assert success is True
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "http://localhost:8000/api/v1/devices/device-uuid-123/network" in args[0]
        assert "connections" in kwargs["json"]


def test_network_monitor_collect_and_diff():
    monitor = NetworkMonitor(long_running_threshold=10.0)

    conn1 = {
        "pid": 500,
        "process_name": "bash",
        "executable_path": "/bin/bash",
        "local_ip": "10.0.0.1",
        "local_port": 5000,
        "remote_ip": "8.8.8.8",
        "remote_port": 53,
        "protocol": "UDP",
        "state": "NONE"
    }

    # Pass 1: First cycle (CONNECTED)
    with patch.object(monitor.collector, "collect", return_value=[conn1]):
        diff1 = monitor.collect_and_diff()
        assert len(diff1["connected"]) == 1
        assert diff1["connected"][0]["pid"] == 500
        assert len(diff1["disconnected"]) == 0
        assert len(diff1["state_changed"]) == 0

    # Pass 2: State changed (SYN_SENT -> ESTABLISHED) & new connection
    conn1_changed = dict(conn1)
    conn1_changed["state"] = "ESTABLISHED"

    conn2 = {
        "pid": 600,
        "process_name": "nc",
        "executable_path": "/usr/bin/nc",
        "local_ip": "10.0.0.1",
        "local_port": 6000,
        "remote_ip": "1.1.1.1",
        "remote_port": 80,
        "protocol": "TCP",
        "state": "ESTABLISHED"
    }

    with patch.object(monitor.collector, "collect", return_value=[conn1_changed, conn2]):
        diff2 = monitor.collect_and_diff()
        assert len(diff2["connected"]) == 1
        assert diff2["connected"][0]["pid"] == 600
        assert len(diff2["state_changed"]) == 1
        assert diff2["state_changed"][0]["old_state"] == "NONE"
        assert diff2["state_changed"][0]["new_state"] == "ESTABLISHED"

    # Pass 3: Disconnected conn1
    with patch.object(monitor.collector, "collect", return_value=[conn2]):
        diff3 = monitor.collect_and_diff()
        assert len(diff3["connected"]) == 0
        assert len(diff3["disconnected"]) == 1
        assert diff3["disconnected"][0]["pid"] == 500
