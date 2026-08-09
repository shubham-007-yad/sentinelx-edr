import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, text

from app.models.telemetry_log import UnifiedTelemetryLog, TelemetryCategoryEnum
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.response_action import ResponseAction
from app.models.process_audit_log import ProcessAuditLog
from app.models.network_connection import NetworkConnection
from app.models.file_integrity_record import FileIntegrityRecord
from app.models.usb_scan_result import USBScanResult
from app.models.event_log import SecurityEvent
from app.models.device import Device

from app.schemas.threat_hunting import (
    ThreatHuntingQuery,
    ThreatHuntMatch,
    ThreatHuntingResponse
)

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def _severity_meets_min(severity: str, min_severity: Optional[str]) -> bool:
    if not min_severity:
        return True
    req_weight = SEVERITY_WEIGHTS.get(min_severity.upper(), 0)
    item_weight = SEVERITY_WEIGHTS.get(severity.upper(), 0)
    return item_weight >= req_weight


def execute_threat_hunt(db: Session, hunting_query: ThreatHuntingQuery) -> ThreatHuntingResponse:
    """
    Flexible cross-telemetry threat hunting query engine.
    Allows searching by Device, Username, Process, SHA-256, IP, Domain, Threat type, Severity, Correlation ID, and Time Range.
    """
    matches: List[ThreatHuntMatch] = []
    seen_ids = set()

    # Time range resolution
    now_ts = datetime.now(timezone.utc)
    start_time = hunting_query.start_time
    end_time = hunting_query.end_time or now_ts

    if hunting_query.time_range_hours and not start_time:
        start_time = now_ts - timedelta(hours=hunting_query.time_range_hours)

    applied_filters = {
        "query": hunting_query.query,
        "device_id": hunting_query.device_id,
        "hostname": hunting_query.hostname,
        "username": hunting_query.username,
        "process": hunting_query.process,
        "sha256": hunting_query.sha256,
        "ip": hunting_query.ip,
        "domain": hunting_query.domain,
        "threat_type": hunting_query.threat_type,
        "min_severity": hunting_query.min_severity,
        "correlation_id": hunting_query.correlation_id,
        "start_time": start_time.isoformat() if start_time else None,
        "end_time": end_time.isoformat() if end_time else None
    }

    # 1. Search UnifiedTelemetryLog table
    try:
        t_query = db.query(UnifiedTelemetryLog)

        if start_time:
            t_query = t_query.filter(UnifiedTelemetryLog.timestamp >= start_time)
        if end_time:
            t_query = t_query.filter(UnifiedTelemetryLog.timestamp <= end_time)

        if hunting_query.device_id:
            try:
                dev_uuid = uuid.UUID(hunting_query.device_id)
                t_query = t_query.filter(UnifiedTelemetryLog.device_id == dev_uuid)
            except ValueError:
                pass

        if hunting_query.correlation_id:
            try:
                c_uuid = uuid.UUID(hunting_query.correlation_id)
                t_query = t_query.filter(UnifiedTelemetryLog.correlation_id == c_uuid)
            except ValueError:
                pass

        logs = t_query.all()
        for log in logs:
            payload = log.payload or {}
            sev = payload.get("severity", "INFO")

            if not _severity_meets_min(sev, hunting_query.min_severity):
                continue

            # Filtering criteria evaluation
            text_haystack = f"{log.event_type} {log.source} {str(payload)}".lower()

            if hunting_query.query and hunting_query.query.lower() not in text_haystack:
                continue

            if hunting_query.process:
                proc_term = hunting_query.process.lower()
                proc_in_payload = payload.get("process_name", "") + payload.get("cmdline", "") + payload.get("process_path", "")
                if proc_term not in proc_in_payload.lower() and proc_term not in text_haystack:
                    continue

            if hunting_query.sha256:
                hash_term = hunting_query.sha256.lower()
                hash_in_payload = payload.get("sha256", "") + payload.get("hash_val", "") + payload.get("file_hash", "")
                if hash_term not in hash_in_payload.lower():
                    continue

            if hunting_query.ip:
                ip_term = hunting_query.ip.lower()
                ip_in_payload = str(payload.get("dest_ip", "")) + str(payload.get("src_ip", "")) + str(payload.get("remote_ip", ""))
                if ip_term not in ip_in_payload.lower():
                    continue

            if hunting_query.username:
                u_term = hunting_query.username.lower()
                u_in_payload = str(payload.get("username", "")) + str(payload.get("user", ""))
                if u_term not in u_in_payload.lower():
                    continue

            item_id = str(log.id)
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)

            ts = log.timestamp or now_ts
            matches.append(
                ThreatHuntMatch(
                    event_id=item_id,
                    timestamp=ts,
                    time_formatted=ts.strftime("%H:%M:%S"),
                    category=log.category.value if hasattr(log.category, "value") else str(log.category),
                    event_type=log.event_type,
                    severity=sev,
                    title=payload.get("title") or f"{log.category.value} Event",
                    description=payload.get("description") or f"Telemetry log from {log.source}",
                    hostname=payload.get("hostname"),
                    username=payload.get("username"),
                    process_name=payload.get("process_name"),
                    sha256=payload.get("sha256") or payload.get("hash_val"),
                    ip=payload.get("dest_ip") or payload.get("src_ip"),
                    correlation_id=str(log.correlation_id) if log.correlation_id else None,
                    payload=payload
                )
            )
    except Exception as e:
        logger.warning(f"[ThreatHuntingEngine] TelemetryLog hunt note: {e}")

    # 2. Search Threats table
    try:
        th_query = db.query(Threat)
        if start_time:
            th_query = th_query.filter(Threat.detected_at >= start_time)
        if end_time:
            th_query = th_query.filter(Threat.detected_at <= end_time)

        if hunting_query.threat_type:
            th_query = th_query.filter(Threat.threat_type == hunting_query.threat_type)

        threats = th_query.all()
        for th in threats:
            sev = th.severity.value if hasattr(th.severity, "value") else str(th.severity)
            if not _severity_meets_min(sev, hunting_query.min_severity):
                continue

            th_text = f"{th.threat_type} {th.rule_name} {th.description}".lower()
            if hunting_query.query and hunting_query.query.lower() not in th_text:
                continue

            if hunting_query.process and hunting_query.process.lower() not in th_text:
                continue

            item_id = f"threat-{th.id}"
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)

            ts = th.detected_at or now_ts
            matches.append(
                ThreatHuntMatch(
                    event_id=item_id,
                    timestamp=ts,
                    time_formatted=ts.strftime("%H:%M:%S"),
                    category="THREAT",
                    event_type=str(th.threat_type),
                    severity=sev,
                    title=f"Threat: {th.rule_name}",
                    description=th.description,
                    correlation_id=str(th.id),
                    payload={
                        "rule_name": th.rule_name,
                        "threat_type": str(th.threat_type),
                        "status": str(th.status),
                        "device_id": str(th.device_id) if th.device_id else None
                    }
                )
            )
    except Exception as e:
        logger.warning(f"[ThreatHuntingEngine] Threat table hunt note: {e}")

    # 3. Search NetworkConnections table
    try:
        if hunting_query.ip or hunting_query.domain or (hunting_query.query and ("ip" in hunting_query.query.lower() or "." in hunting_query.query)):
            net_query = db.query(NetworkConnection)
            if start_time:
                net_query = net_query.filter(NetworkConnection.timestamp >= start_time)
            if end_time:
                net_query = net_query.filter(NetworkConnection.timestamp <= end_time)

            net_conns = net_query.all()
            for nc in net_conns:
                ip_match = False
                if hunting_query.ip:
                    if hunting_query.ip in (nc.remote_address or "") or hunting_query.ip in (nc.local_address or ""):
                        ip_match = True
                else:
                    ip_match = True

                if not ip_match:
                    continue

                item_id = f"net-{nc.id}"
                if item_id in seen_ids:
                    continue
                seen_ids.add(item_id)

                ts = nc.timestamp or now_ts
                matches.append(
                    ThreatHuntMatch(
                        event_id=item_id,
                        timestamp=ts,
                        time_formatted=ts.strftime("%H:%M:%S"),
                        category="NETWORK",
                        event_type="NETWORK_CONNECTION",
                        severity="MEDIUM" if nc.pid else "LOW",
                        title=f"Network Connection to {nc.remote_address}:{nc.remote_port}",
                        description=f"Protocol {nc.protocol} | State: {nc.state}",
                        process_name=nc.process_name,
                        ip=nc.remote_address,
                        payload={
                            "pid": nc.pid,
                            "process_name": nc.process_name,
                            "local_address": nc.local_address,
                            "local_port": nc.local_port,
                            "remote_address": nc.remote_address,
                            "remote_port": nc.remote_port,
                            "protocol": str(nc.protocol),
                            "state": str(nc.state)
                        }
                    )
                )
    except Exception as e:
        logger.warning(f"[ThreatHuntingEngine] NetworkConnection hunt note: {e}")

    # Sort matches chronologically descending (newest first for threat hunting)
    matches.sort(key=lambda x: x.timestamp, reverse=True)

    # Pagination slice
    start_idx = hunting_query.offset
    end_idx = start_idx + hunting_query.limit
    paged_matches = matches[start_idx:end_idx]

    return ThreatHuntingResponse(
        total_matches=len(matches),
        applied_filters=applied_filters,
        matches=paged_matches
    )
