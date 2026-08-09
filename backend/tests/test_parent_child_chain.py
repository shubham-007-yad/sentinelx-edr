import pytest
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.alert import Alert
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.rules.parent_child_chain import ParentChildChainRule
from app.schemas.process import ProcessInfoCreate
from app.services.process_service import ingest_processes


def test_office_spawning_cmd_chain():
    rule = ParentChildChainRule()

    # 1. Word spawning CMD
    res = rule.evaluate_process_chain(
        pid=2048,
        name="cmd.exe",
        ppid=1024,
        parent_name="winword.exe",
        cmdline="cmd.exe /c calc.exe"
    )
    assert res is not None
    assert res.severity == ThreatSeverity.CRITICAL
    assert res.threat_type == ThreatType.SUSPICIOUS_PROCESS_BEHAVIOR
    assert "winword.exe" in res.description
    assert "cmd.exe" in res.description


def test_shell_to_shell_evasion_chain():
    rule = ParentChildChainRule()

    # 2. PowerShell spawning CMD
    res = rule.evaluate_process_chain(
        pid=3000,
        name="cmd.exe",
        ppid=2000,
        parent_name="powershell.exe",
        cmdline="cmd.exe /c echo test"
    )
    assert res is not None
    assert res.severity == ThreatSeverity.HIGH
    assert "powershell.exe" in res.description


def test_ingest_process_chain_alert():
    db = SessionLocal()
    try:
        device = Device(
            hostname="chain-test-host",
            ip_address="192.168.1.220",
            mac_address="AA:BB:CC:DD:EE:66",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # Process snapshot containing Word spawning PowerShell
        proc_payload = [
            ProcessInfoCreate(
                pid=1000,
                ppid=1,
                name="winword.exe",
                exe_path="C:\\Program Files\\Microsoft Office\\winword.exe",
                username="user"
            ),
            ProcessInfoCreate(
                pid=2000,
                ppid=1000,
                name="powershell.exe",
                exe_path="C:\\Windows\\System32\\powershell.exe",
                username="user",
                cmdline="powershell.exe -w hidden -enc ..."
            )
        ]

        ingest_processes(db=db, device_id=device.id, processes_in=proc_payload)

        alerts = db.query(Alert).filter(Alert.device_id == device.id).all()
        assert len(alerts) >= 1
        messages = [a.message for a in alerts]
        assert any("winword.exe" in m or "PowerShell" in m for m in messages)

    finally:
        db.close()
