import uuid
from datetime import datetime, timezone, timedelta
import pytest

from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.schemas.threat_hunting import ThreatHuntingQuery
from app.schemas.timeline import SequenceEventItem
from app.services.timeline_engine import ingest_correlated_sequence
from app.services.threat_hunting_engine import execute_threat_hunt


def test_threat_hunting_query_engine():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        device = Device(
            hostname="hunting-host-01",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()

        device_id = device.id
        correlation_id = str(uuid.uuid4())
        now_ts = datetime.now(timezone.utc)

        # Ingest test telemetry data with various processes and severities
        events = [
            SequenceEventItem(
                category="PROCESS",
                title="cmd.exe execution",
                description="Normal cmd execution",
                severity="LOW",
                timestamp=now_ts - timedelta(hours=2),
                metadata={"process_name": "cmd.exe", "username": "admin"}
            ),
            SequenceEventItem(
                category="PROCESS",
                title="powershell.exe started",
                description="Malicious powershell -ExecutionPolicy Bypass script",
                severity="HIGH",
                timestamp=now_ts - timedelta(hours=1),
                metadata={"process_name": "powershell.exe", "username": "victim_user", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            ),
            SequenceEventItem(
                category="NETWORK",
                title="Outbound C2 connection",
                description="Outbound connection to malicious C2 server",
                severity="CRITICAL",
                timestamp=now_ts - timedelta(minutes=30),
                metadata={"process_name": "powershell.exe", "dest_ip": "198.51.100.99", "domain": "malicious-c2.com"}
            )
        ]

        ingest_correlated_sequence(
            db=db,
            device_id=device_id,
            correlation_id=correlation_id,
            events=events
        )

        # 1. Test query: process = powershell.exe AND severity >= HIGH AND Last 24 hours
        hunt_query_1 = ThreatHuntingQuery(
            process="powershell.exe",
            min_severity="HIGH",
            time_range_hours=24.0
        )
        res_1 = execute_threat_hunt(db, hunt_query_1)

        assert res_1 is not None
        assert res_1.total_matches >= 2  # powershell.exe HIGH + powershell.exe CRITICAL
        for match in res_1.matches:
            assert match.severity in ["HIGH", "CRITICAL"]
            assert "powershell" in (match.process_name or match.title or match.description).lower()

        # 2. Test query by IP
        hunt_query_ip = ThreatHuntingQuery(
            ip="198.51.100.99",
            time_range_hours=24.0
        )
        res_ip = execute_threat_hunt(db, hunt_query_ip)
        assert res_ip.total_matches >= 1

        # 3. Test query by SHA256
        hunt_query_hash = ThreatHuntingQuery(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        res_hash = execute_threat_hunt(db, hunt_query_hash)
        assert res_hash.total_matches >= 1

        # 4. Test query by Correlation ID
        hunt_query_corr = ThreatHuntingQuery(
            correlation_id=correlation_id
        )
        res_corr = execute_threat_hunt(db, hunt_query_corr)
        assert res_corr.total_matches >= 3

    finally:
        db.close()
