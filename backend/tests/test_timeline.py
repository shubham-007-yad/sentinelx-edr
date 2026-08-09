import uuid
from datetime import datetime, timezone, timedelta
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.services.timeline_engine import get_unified_timeline, ingest_correlated_sequence
from app.schemas.timeline import SequenceEventItem


def test_unified_timeline_sequence():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        device = Device(
            hostname="timeline-host",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()

        device_id = device.id
        correlation_id = str(uuid.uuid4())

        base_time = datetime.now(timezone.utc)

        # 8-step incident timeline sequence
        events = [
            SequenceEventItem(
                category="USB",
                title="USB inserted",
                description="Removable drive E: connected",
                severity="INFO",
                timestamp=base_time
            ),
            SequenceEventItem(
                category="USB",
                title="USB scan started",
                description="ClamAV scan initiated on drive E:",
                severity="INFO",
                timestamp=base_time + timedelta(seconds=10)
            ),
            SequenceEventItem(
                category="PROCESS",
                title="installer.exe detected",
                description="Suspicious executable detected in E:\\installer.exe",
                severity="HIGH",
                timestamp=base_time + timedelta(seconds=60)
            ),
            SequenceEventItem(
                category="THREAT",
                title="Threat created",
                description="Behavioral Threat: Suspicious USB Executable",
                severity="CRITICAL",
                timestamp=base_time + timedelta(seconds=65)
            ),
            SequenceEventItem(
                category="PROCESS",
                title="powershell.exe started",
                description="Spawned powershell.exe -ExecutionPolicy Bypass",
                severity="HIGH",
                timestamp=base_time + timedelta(seconds=120)
            ),
            SequenceEventItem(
                category="NETWORK",
                title="Network connection opened",
                description="Outbound TCP connection to 198.51.100.45:443",
                severity="HIGH",
                timestamp=base_time + timedelta(seconds=130)
            ),
            SequenceEventItem(
                category="ALERT",
                title="Alert generated",
                description="ALERT: High Risk C2 Communication",
                severity="CRITICAL",
                timestamp=base_time + timedelta(seconds=180)
            ),
            SequenceEventItem(
                category="RESPONSE",
                title="Endpoint isolated",
                description="Host network interfaces isolated automatically",
                severity="CRITICAL",
                timestamp=base_time + timedelta(seconds=185)
            )
        ]

        res = ingest_correlated_sequence(
            db=db,
            device_id=device_id,
            correlation_id=correlation_id,
            events=events
        )

        assert res is not None
        assert res.correlation_id == correlation_id
        assert res.total_events >= 8

        # Verify chronological ordering
        titles = [item.title for item in res.timeline]
        assert "USB inserted" in titles
        assert "USB scan started" in titles
        assert "installer.exe detected" in titles
        assert "Threat created" in titles
        assert "powershell.exe started" in titles
        assert "Network connection opened" in titles
        assert "Alert generated" in titles
        assert "Endpoint isolated" in titles
    finally:
        db.close()
