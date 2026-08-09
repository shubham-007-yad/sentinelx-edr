"""
Trend Analysis & Time-Series Engine Module
Computes daily/weekly incident trends, directional shifts, threat velocity indicators,
and multi-stream chart analytics (Threats, Alerts, Endpoint Activity, USB, Network, Process).
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone, date
from collections import defaultdict
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertSeverity
from app.models.threat import Threat
from app.models.response_action import ResponseAction, ResponseActionStatus
from app.models.device import Device
from app.models.usb_event import USBEvent
from app.models.network_connection import NetworkConnection
from app.models.process_audit_log import ProcessAuditLog
from app.models.telemetry_log import UnifiedTelemetryLog


class TrendAnalyzer:
    def __init__(self, db: Session):
        self.db = db

    def get_daily_incident_trends(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Generates daily time-series incident counts broken down by severity
        for chart rendering (e.g. line or stacked bar charts).
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=days - 1)
        start_date = start_time.date()
        end_date = now.date()

        daily_map = {}
        curr = start_date
        while curr <= end_date:
            daily_map[curr.isoformat()] = {
                "date": curr.isoformat(),
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
            curr += timedelta(days=1)

        alerts = self.db.query(Alert).filter(Alert.created_at >= start_time).all()
        for alert in alerts:
            if alert.created_at:
                d_str = alert.created_at.date().isoformat()
                if d_str in daily_map:
                    daily_map[d_str]["total"] += 1
                    sev_key = alert.severity.value.lower() if hasattr(alert.severity, 'value') else str(alert.severity).lower()
                    if sev_key in daily_map[d_str]:
                        daily_map[d_str][sev_key] += 1

        result = list(daily_map.values())
        result.sort(key=lambda x: x["date"])
        return result

    def get_trend_velocity(self, period_days: int = 7) -> Dict[str, Any]:
        """
        Compares the current N-day window against the previous N-day window
        to calculate directional percentage changes and velocity indicators.
        """
        now = datetime.now(timezone.utc)
        current_start = now - timedelta(days=period_days)
        previous_start = current_start - timedelta(days=period_days)

        curr_alerts = self.db.query(Alert).filter(
            Alert.created_at >= current_start,
            Alert.created_at <= now
        ).all()
        curr_critical = sum(1 for a in curr_alerts if a.severity == AlertSeverity.CRITICAL)

        prev_alerts = self.db.query(Alert).filter(
            Alert.created_at >= previous_start,
            Alert.created_at < current_start
        ).all()
        prev_critical = sum(1 for a in prev_alerts if a.severity == AlertSeverity.CRITICAL)

        def pct_change(curr: int, prev: int) -> float:
            if prev == 0:
                return 100.0 if curr > 0 else 0.0
            return round(((curr - prev) / prev) * 100.0, 1)

        alert_volume_change_pct = pct_change(len(curr_alerts), len(prev_alerts))
        critical_change_pct = pct_change(curr_critical, prev_critical)

        if alert_volume_change_pct > 10.0:
            overall_direction = "INCREASING"
        elif alert_volume_change_pct < -10.0:
            overall_direction = "DECREASING"
        else:
            overall_direction = "STABLE"

        return {
            "period_days": period_days,
            "current_period_alerts": len(curr_alerts),
            "previous_period_alerts": len(prev_alerts),
            "alert_volume_change_pct": alert_volume_change_pct,
            "current_critical_alerts": curr_critical,
            "previous_critical_alerts": prev_critical,
            "critical_change_pct": critical_change_pct,
            "overall_direction": overall_direction,
        }

    def get_multi_stream_trends(
        self,
        timeframe: str = "7d",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Computes time-series trend data for 6 core telemetry streams:
        1. Threats per day/hour
        2. Alerts per day/hour
        3. Endpoint activity
        4. USB insertions
        5. Network detections
        6. Process detections

        Supports timeframes: '24h', '7d', '30d', or 'custom' with start_date & end_date.
        """
        now = datetime.now(timezone.utc)
        use_hourly = False

        if timeframe == "24h":
            use_hourly = True
            end_time = now
            start_time = now - timedelta(hours=24)
        elif timeframe == "7d":
            use_hourly = False
            end_time = now
            start_time = now - timedelta(days=6)
        elif timeframe == "30d":
            use_hourly = False
            end_time = now
            start_time = now - timedelta(days=29)
        elif timeframe == "custom":
            start_time = start_date if start_date else (now - timedelta(days=30))
            end_time = end_date if end_date else now
            if (end_time - start_time).total_seconds() <= 172800:  # <= 48 hours
                use_hourly = True
            else:
                use_hourly = False
        else:
            # Default to 7d
            use_hourly = False
            end_time = now
            start_time = now - timedelta(days=6)

        # Build bucket keys
        buckets: Dict[str, Dict[str, Any]] = {}

        if use_hourly:
            curr = start_time.replace(minute=0, second=0, microsecond=0)
            target_end = end_time.replace(minute=0, second=0, microsecond=0)
            while curr <= target_end:
                key = curr.strftime("%Y-%m-%d %H:00")
                buckets[key] = {
                    "timestamp": key,
                    "threats": 0,
                    "alerts": 0,
                    "endpoint_activity": 0,
                    "usb_insertions": 0,
                    "network_detections": 0,
                    "process_detections": 0,
                }
                curr += timedelta(hours=1)
        else:
            curr_date = start_time.date()
            end_d = end_time.date()
            while curr_date <= end_d:
                key = curr_date.isoformat()
                buckets[key] = {
                    "timestamp": key,
                    "threats": 0,
                    "alerts": 0,
                    "endpoint_activity": 0,
                    "usb_insertions": 0,
                    "network_detections": 0,
                    "process_detections": 0,
                }
                curr_date += timedelta(days=1)

        def get_key(dt: Optional[datetime]) -> Optional[str]:
            if not dt:
                return None
            if use_hourly:
                return dt.strftime("%Y-%m-%d %H:00")
            return dt.date().isoformat()

        # 1. Threats
        threats = self.db.query(Threat).filter(Threat.detected_at >= start_time, Threat.detected_at <= end_time).all()
        for t in threats:
            k = get_key(t.detected_at)
            if k in buckets:
                buckets[k]["threats"] += 1

        # 2. Alerts
        alerts = self.db.query(Alert).filter(Alert.created_at >= start_time, Alert.created_at <= end_time).all()
        for a in alerts:
            k = get_key(a.created_at)
            if k in buckets:
                buckets[k]["alerts"] += 1

        # 3. Endpoint Activity (Telemetry logs + Active device heartbeats)
        telemetry_logs = self.db.query(UnifiedTelemetryLog).filter(UnifiedTelemetryLog.timestamp >= start_time, UnifiedTelemetryLog.timestamp <= end_time).all()
        for tl in telemetry_logs:
            k = get_key(tl.timestamp)
            if k in buckets:
                buckets[k]["endpoint_activity"] += 1

        devices = self.db.query(Device).filter(Device.last_seen >= start_time, Device.last_seen <= end_time).all()
        for dev in devices:
            k = get_key(dev.last_seen)
            if k in buckets:
                buckets[k]["endpoint_activity"] += 1

        # 4. USB Insertions
        usb_events = self.db.query(USBEvent).filter(USBEvent.detected_at >= start_time, USBEvent.detected_at <= end_time).all()
        for u in usb_events:
            k = get_key(u.detected_at)
            if k in buckets:
                buckets[k]["usb_insertions"] += 1

        # 5. Network Detections
        net_conns = self.db.query(NetworkConnection).filter(NetworkConnection.created_at >= start_time, NetworkConnection.created_at <= end_time).all()
        for n in net_conns:
            k = get_key(n.created_at)
            if k in buckets:
                buckets[k]["network_detections"] += 1

        # 6. Process Detections
        proc_logs = self.db.query(ProcessAuditLog).filter(ProcessAuditLog.timestamp >= start_time, ProcessAuditLog.timestamp <= end_time).all()
        for p in proc_logs:
            k = get_key(p.timestamp)
            if k in buckets:
                buckets[k]["process_detections"] += 1

        sorted_buckets = sorted(buckets.values(), key=lambda x: x["timestamp"])

        # Format separate time-series for easy frontend chart rendering
        threats_series = [{"time": b["timestamp"], "value": b["threats"]} for b in sorted_buckets]
        alerts_series = [{"time": b["timestamp"], "value": b["alerts"]} for b in sorted_buckets]
        endpoint_series = [{"time": b["timestamp"], "value": b["endpoint_activity"]} for b in sorted_buckets]
        usb_series = [{"time": b["timestamp"], "value": b["usb_insertions"]} for b in sorted_buckets]
        network_series = [{"time": b["timestamp"], "value": b["network_detections"]} for b in sorted_buckets]
        process_series = [{"time": b["timestamp"], "value": b["process_detections"]} for b in sorted_buckets]

        return {
            "timeframe": timeframe,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "granularity": "hourly" if use_hourly else "daily",
            "combined_buckets": sorted_buckets,
            "series": {
                "threats_per_day": threats_series,
                "alerts_per_day": alerts_series,
                "endpoint_activity": endpoint_series,
                "usb_insertions": usb_series,
                "network_detections": network_series,
                "process_detections": process_series,
            }
        }
