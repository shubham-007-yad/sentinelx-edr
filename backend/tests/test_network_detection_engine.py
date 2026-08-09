import time
import pytest
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.network import (
    NetworkDetectionEngine,
    SuspiciousPortRule,
    BlacklistedIPRule,
    ExcessiveConnectionsRule,
    UnexpectedInternetAccessRule,
    BeaconingDetectionRule,
    LocalIPReputationProvider
)


def test_suspicious_port_rule():
    rule = SuspiciousPortRule()
    # Matched suspicious remote port 4444
    res = rule.evaluate_connection(
        pid=1234,
        process_name="nc",
        local_ip="192.168.1.50",
        local_port=54321,
        remote_ip="1.2.3.4",
        remote_port=4444,
        protocol="TCP",
        state="ESTABLISHED"
    )
    assert res is not None
    assert res.threat_type == ThreatType.SUSPICIOUS_NETWORK_PORT
    assert res.severity == ThreatSeverity.HIGH
    assert "port 4444" in res.description

    # Normal port 80 - no hit
    res_normal = rule.evaluate_connection(
        pid=1234,
        process_name="curl",
        local_ip="192.168.1.50",
        local_port=54322,
        remote_ip="93.184.216.34",
        remote_port=80,
        protocol="TCP"
    )
    assert res_normal is None


def test_blacklisted_ip_rule():
    rule = BlacklistedIPRule()
    # Blacklisted IP 185.220.101.5
    res = rule.evaluate_connection(
        pid=2000,
        process_name="malware.exe",
        remote_ip="185.220.101.5",
        remote_port=443
    )
    assert res is not None
    assert res.threat_type == ThreatType.BLACK_LISTED_IP
    assert res.severity == ThreatSeverity.HIGH
    assert "185.220.101.5" in res.description

    # Clean IP
    res_clean = rule.evaluate_connection(
        pid=2000,
        process_name="browser.exe",
        remote_ip="8.8.8.8",
        remote_port=53
    )
    assert res_clean is None


def test_excessive_connections_rule():
    rule = ExcessiveConnectionsRule(connection_threshold=5)

    # 10 connections for powershell.exe
    batch = [
        {
            "pid": 3000,
            "process_name": "powershell.exe",
            "local_ip": "192.168.1.50",
            "local_port": 5000 + i,
            "remote_ip": f"10.0.0.{i}",
            "remote_port": 80,
            "protocol": "TCP"
        }
        for i in range(10)
    ]

    engine = NetworkDetectionEngine(rules=[rule])
    findings = engine.evaluate_connection_batch(batch)
    assert len(findings) >= 1
    excessive_hit = [f for f in findings if f.threat_type == ThreatType.EXCESSIVE_CONNECTIONS]
    assert len(excessive_hit) == 1
    assert "10 active outbound connections" in excessive_hit[0].description


def test_unexpected_internet_access_rule():
    rule = UnexpectedInternetAccessRule()

    # powershell.exe connecting directly to external IP 93.184.216.34
    res = rule.evaluate_connection(
        pid=4000,
        process_name="powershell.exe",
        local_ip="192.168.1.50",
        local_port=49152,
        remote_ip="93.184.216.34",
        remote_port=443,
        protocol="TCP"
    )
    assert res is not None
    assert res.threat_type == ThreatType.UNEXPECTED_INTERNET_ACCESS
    assert res.severity == ThreatSeverity.HIGH
    assert "powershell.exe" in res.description

    # powershell.exe connecting to internal private IP 192.168.1.1 - no hit
    res_internal = rule.evaluate_connection(
        pid=4000,
        process_name="powershell.exe",
        local_ip="192.168.1.50",
        local_port=49153,
        remote_ip="192.168.1.1",
        remote_port=443
    )
    assert res_internal is None


def test_beaconing_detection_rule():
    rule = BeaconingDetectionRule(min_samples=3, max_interval_variance=2.0)

    now = time.time()
    # Simulate 3 periodic connection attempts every 10 seconds
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(time, "time", lambda: now)
        res1 = rule.evaluate_connection(pid=5000, process_name="agent.exe", remote_ip="203.0.113.50", remote_port=443)
        assert res1 is None

        mp.setattr(time, "time", lambda: now + 10.0)
        res2 = rule.evaluate_connection(pid=5000, process_name="agent.exe", remote_ip="203.0.113.50", remote_port=443)
        assert res2 is None

        mp.setattr(time, "time", lambda: now + 20.0)
        res3 = rule.evaluate_connection(pid=5000, process_name="agent.exe", remote_ip="203.0.113.50", remote_port=443)
        assert res3 is not None
        assert res3.threat_type == ThreatType.C2_BEACONING
        assert "Beaconing" in res3.description
