"""
Telemetry & Event Aggregator Module
Aggregates raw telemetry, alerts, threats, and response logs into structured data buckets.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, case, desc, and_

from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.device import Device, DeviceStatus
from app.models.response_action import ResponseAction, ResponseActionStatus, ResponseActionType
from app.models.telemetry_log import UnifiedTelemetryLog
from app.models.event_log import SecurityEvent
from app.models.file_integrity_record import FileIntegrityRecord
from app.models.usb_event import USBEvent
from app.models.network_connection import NetworkConnection


class TelemetryAggregator:
    def __init__(self, db: Session):
        self.db = db

    def get_time_bounds(self, timeframe_days: int = 7) -> tuple[datetime, datetime]:
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=timeframe_days)
        return start, now

    def aggregate_alerts_by_severity(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Aggregate total alerts by severity level."""
        query = self.db.query(Alert.severity, func.count(Alert.id))
        if start_time:
            query = query.filter(Alert.created_at >= start_time)
        if end_time:
            query = query.filter(Alert.created_at <= end_time)

        results = query.group_by(Alert.severity).all()
        
        # Initialize defaults
        counts = {sev.value: 0 for sev in AlertSeverity}
        for sev, count in results:
            key = sev.value if hasattr(sev, 'value') else str(sev)
            counts[key] = count
        return counts

    def aggregate_alerts_by_status(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Aggregate alerts by resolution/acknowledgement status."""
        query = self.db.query(Alert.status, func.count(Alert.id))
        if start_time:
            query = query.filter(Alert.created_at >= start_time)
        if end_time:
            query = query.filter(Alert.created_at <= end_time)

        results = query.group_by(Alert.status).all()
        counts = {stat.value: 0 for stat in AlertStatus}
        for stat, count in results:
            key = stat.value if hasattr(stat, 'value') else str(stat)
            counts[key] = count
        return counts

    def aggregate_threats_by_type(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Aggregate threat counts by threat type/category."""
        query = self.db.query(Threat.threat_type, func.count(Threat.id).label("count"))
        if start_time:
            query = query.filter(Threat.detected_at >= start_time)
        if end_time:
            query = query.filter(Threat.detected_at <= end_time)

        results = query.group_by(Threat.threat_type).order_by(desc("count")).limit(limit).all()
        return [
            {
                "threat_type": tt.value if hasattr(tt, 'value') else str(tt),
                "count": count
            }
            for tt, count in results
        ]

    def aggregate_device_alert_distribution(
        self, start_time: Optional[datetime] = None, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Find endpoints with the highest volume of alerts and breakdown by severity."""
        query = self.db.query(
            Device.id,
            Device.hostname,
            Device.status,
            Device.os_type,
            func.count(Alert.id).label("total_alerts"),
            func.sum(case((Alert.severity == AlertSeverity.CRITICAL, 1), else_=0)).label("critical_count"),
            func.sum(case((Alert.severity == AlertSeverity.HIGH, 1), else_=0)).label("high_count"),
            func.sum(case((Alert.severity == AlertSeverity.MEDIUM, 1), else_=0)).label("medium_count"),
            func.sum(case((Alert.severity == AlertSeverity.LOW, 1), else_=0)).label("low_count")
        ).join(Alert, Device.id == Alert.device_id)

        if start_time:
            query = query.filter(Alert.created_at >= start_time)

        results = (
            query.group_by(Device.id, Device.hostname, Device.status, Device.os_type)
            .order_by(desc("total_alerts"))
            .limit(limit)
            .all()
        )

        return [
            {
                "device_id": str(r[0]),
                "hostname": r[1],
                "status": r[2].value if hasattr(r[2], 'value') else str(r[2]),
                "os_type": r[3].value if hasattr(r[3], 'value') else str(r[3]),
                "total_alerts": r[4],
                "critical_count": r[5] or 0,
                "high_count": r[6] or 0,
                "medium_count": r[7] or 0,
                "low_count": r[8] or 0,
            }
            for r in results
        ]

    def aggregate_responses_by_status(
        self, start_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Aggregate total response actions by execution status (SUCCESS, FAILED, PENDING, etc.)."""
        query = self.db.query(ResponseAction.status, func.count(ResponseAction.id))
        if start_time:
            query = query.filter(ResponseAction.started_at >= start_time)

        results = query.group_by(ResponseAction.status).all()
        counts = {st.value: 0 for st in ResponseActionStatus}
        for st, count in results:
            key = st.value if hasattr(st, 'value') else str(st)
            counts[key] = count
        return counts

    def aggregate_responses_by_type(
        self, start_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Aggregate total response actions by response action type (QUARANTINE, ISOLATE, etc.)."""
        query = self.db.query(ResponseAction.action_type, func.count(ResponseAction.id))
        if start_time:
            query = query.filter(ResponseAction.started_at >= start_time)

        results = query.group_by(ResponseAction.action_type).all()
        return {
            (act.value if hasattr(act, 'value') else str(act)): count
            for act, count in results
        }

    def aggregate_telemetry_totals(self, start_time: Optional[datetime] = None) -> Dict[str, int]:
        """Get aggregate counts across all telemetry sources (processes, network, FIM, USB, security events)."""
        def count_table(model, date_col):
            q = self.db.query(func.count(model.id))
            if start_time and hasattr(model, date_col):
                q = q.filter(getattr(model, date_col) >= start_time)
            return q.scalar() or 0

        return {
            "telemetry_logs": count_table(UnifiedTelemetryLog, "timestamp"),
            "security_events": count_table(SecurityEvent, "event_timestamp"),
            "file_integrity_records": count_table(FileIntegrityRecord, "timestamp"),
            "usb_events": count_table(USBEvent, "timestamp"),
            "network_connections": count_table(NetworkConnection, "timestamp"),
        }
