import uuid
import pytest
from app.detection.behavior.incident_correlator import IncidentCorrelationEngine


def test_cross_telemetry_correlation_single_incident():
    """
    Phase 6 Verification Test:
    Verifies that a 6-step multi-subsystem attack sequence:
    1. USB Insert
    2. installer.exe (Process)
    3. Process Started (Child execution)
    4. Network Connection (C2 egress)
    5. IOC Match (Threat Intel)
    6. Ransomware Behavior (Mass encryption)
    7. Response (Endpoint isolation)

    Results in ONE unified correlated incident, NOT six separate disjoint alerts.
    """
    engine = IncidentCorrelationEngine(correlation_window_seconds=600.0)
    device_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())

    # Step 1: USB Insert
    inc1 = engine.correlate_event(
        device_id=device_id,
        subsystem="USB",
        rule_name="USB Insert",
        description="Removable USB Drive E: inserted",
        severity="INFO",
        raw_payload={"drive_letter": "E:"},
        existing_correlation_id=correlation_id
    )

    # Step 2: installer.exe Execution
    inc2 = engine.correlate_event(
        device_id=device_id,
        subsystem="PROCESS",
        rule_name="installer.exe",
        description="Execution of untrusted E:\\installer.exe",
        severity="HIGH",
        process_name="installer.exe",
        pid=4096,
        existing_correlation_id=correlation_id
    )

    # Step 3: Process Started (Child powershell.exe)
    inc3 = engine.correlate_event(
        device_id=device_id,
        subsystem="PROCESS",
        rule_name="Process Started",
        description="Spawned powershell.exe -ExecutionPolicy Bypass",
        severity="HIGH",
        process_name="powershell.exe",
        pid=5120,
        existing_correlation_id=correlation_id
    )

    # Step 4: Network Connection
    inc4 = engine.correlate_event(
        device_id=device_id,
        subsystem="NETWORK",
        rule_name="Network Connection",
        description="Outbound TCP connection to 198.51.100.99:443",
        severity="HIGH",
        remote_ip="198.51.100.99",
        pid=5120,
        existing_correlation_id=correlation_id
    )

    # Step 5: IOC Match
    inc5 = engine.correlate_event(
        device_id=device_id,
        subsystem="THREAT",
        rule_name="IOC Match",
        description="Matched C2 IP 198.51.100.99 in Threat Intel feed",
        severity="CRITICAL",
        existing_correlation_id=correlation_id
    )

    # Step 6: Ransomware Behavior
    inc6 = engine.correlate_event(
        device_id=device_id,
        subsystem="RANSOMWARE",
        rule_name="Ransomware Behavior",
        description="Mass high-entropy file encryption detected (50 files/sec)",
        severity="CRITICAL",
        existing_correlation_id=correlation_id
    )

    # Step 7: Response Action
    inc7 = engine.correlate_event(
        device_id=device_id,
        subsystem="RESPONSE",
        rule_name="Response",
        description="Host network interfaces isolated & process 5120 killed automatically",
        severity="CRITICAL",
        existing_correlation_id=correlation_id
    )

    # Key Assertion 1: Analyst sees ONE unified incident, not separate disjoint alerts
    all_incidents = engine.list_unified_incidents(device_id=device_id)
    assert len(all_incidents) == 1, f"Expected 1 unified incident, found {len(all_incidents)}"

    unified_inc = all_incidents[0]
    assert unified_inc["correlation_id"] == correlation_id
    assert unified_inc["total_correlated_alerts"] == 7
    assert unified_inc["severity"] == "CRITICAL"
    assert "USB Drive Insertion" in unified_inc["root_cause_vector"]

    # Key Assertion 2: All 6 subsystems are represented in the single incident attack chain
    subsystems = unified_inc["subsystems_involved"]
    assert "USB" in subsystems
    assert "PROCESS" in subsystems
    assert "NETWORK" in subsystems
    assert "THREAT" in subsystems
    assert "RANSOMWARE" in subsystems
    assert "RESPONSE" in subsystems

    # Key Assertion 3: Step-by-step attack storyline is preserved sequentially
    attack_chain = unified_inc["attack_chain_summary"]
    actions = [step["action"] for step in attack_chain]
    assert actions == [
        "USB Insert",
        "installer.exe",
        "Process Started",
        "Network Connection",
        "IOC Match",
        "Ransomware Behavior",
        "Response"
    ]
