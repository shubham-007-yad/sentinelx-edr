import pytest
from app.detection.behavior.incident_correlator import IncidentCorrelationEngine, UnifiedIncident


def test_unified_incident_correlation_chain():
    engine = IncidentCorrelationEngine(correlation_window_seconds=300.0)
    device_id = "DEV-FINANCE-001"

    # Step 1: USB inserted
    inc1 = engine.correlate_event(
        device_id=device_id,
        subsystem="USB",
        rule_name="USB Removable Storage Insertion",
        description="Removable USB Drive (E:) connected to host",
        severity="MEDIUM",
        raw_payload={"drive_letter": "E:", "volume_label": "ATTACK_USB"}
    )
    correlation_id = inc1.correlation_id

    # Step 2: installer.exe executed from USB
    inc2 = engine.correlate_event(
        device_id=device_id,
        subsystem="PROCESS",
        rule_name="Executable Launched From Removable Storage",
        description="Process installer.exe spawned from E:\\installer.exe",
        severity="HIGH",
        pid=6120,
        process_name="installer.exe",
        existing_correlation_id=correlation_id
    )

    # Step 3: powershell launched by installer.exe
    inc3 = engine.correlate_event(
        device_id=device_id,
        subsystem="PROCESS",
        rule_name="Parent-Child Chain: Installer to PowerShell",
        description="installer.exe (PID 6120) spawned powershell.exe -Enc",
        severity="HIGH",
        pid=7840,
        process_name="powershell.exe",
        existing_correlation_id=correlation_id
    )

    # Step 4: Network C2 connection
    inc4 = engine.correlate_event(
        device_id=device_id,
        subsystem="NETWORK",
        rule_name="Outbound C2 Socket Connection",
        description="powershell.exe established socket to 185.220.101.5:443",
        severity="HIGH",
        pid=7840,
        process_name="powershell.exe",
        remote_ip="185.220.101.5",
        existing_correlation_id=correlation_id
    )

    # Step 5: Mass file encryption
    inc5 = engine.correlate_event(
        device_id=device_id,
        subsystem="RANSOMWARE",
        rule_name="Mass File Encryption Burst & Extension Mutation",
        description="powershell.exe encrypted 350 files and appended .locked extension",
        severity="CRITICAL",
        pid=7840,
        process_name="powershell.exe",
        existing_correlation_id=correlation_id
    )

    # Verify that all 5 alerts were unified under ONE single incident
    assert inc5.correlation_id == correlation_id
    assert len(inc5.events) == 5
    assert inc5.to_dict()["total_correlated_alerts"] == 5
    assert inc5.severity == "CRITICAL"
    assert inc5.composite_score == 95.0
    assert "USB Drive Insertion" in inc5.root_cause_vector
    
    subsystems = inc5.to_dict()["subsystems_involved"]
    assert "USB" in subsystems
    assert "PROCESS" in subsystems
    assert "NETWORK" in subsystems
    assert "RANSOMWARE" in subsystems

    # Check attack chain summary steps
    summary = inc5.attack_chain_summary
    assert len(summary) == 5
    assert summary[0]["subsystem"] == "USB"
    assert summary[1]["subsystem"] == "PROCESS"
    assert summary[2]["subsystem"] == "PROCESS"
    assert summary[3]["subsystem"] == "NETWORK"
    assert summary[4]["subsystem"] == "RANSOMWARE"


def test_multiple_isolated_devices_have_distinct_correlation_ids():
    engine = IncidentCorrelationEngine()
    
    incA = engine.correlate_event(
        device_id="DEV-A",
        subsystem="USB",
        rule_name="USB Inserted",
        description="USB on A"
    )

    incB = engine.correlate_event(
        device_id="DEV-B",
        subsystem="USB",
        rule_name="USB Inserted",
        description="USB on B"
    )

    assert incA.correlation_id != incB.correlation_id
    assert len(engine.list_unified_incidents()) == 2
