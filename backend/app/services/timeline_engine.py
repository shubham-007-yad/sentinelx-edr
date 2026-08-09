import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.telemetry_log import UnifiedTelemetryLog, TelemetryCategoryEnum
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.response_action import ResponseAction
from app.models.usb_event import USBEvent
from app.models.file_integrity_record import FileIntegrityRecord
from app.models.process_audit_log import ProcessAuditLog
from app.models.network_connection import NetworkConnection
from app.models.event_log import SecurityEvent

from app.schemas.timeline import (
    TimelineEventItem,
    UnifiedTimelineResponse,
    SequenceEventItem
)
from app.detection.behavior.incident_correlator import IncidentCorrelationEngine

logger = logging.getLogger(__name__)

# Global singleton or shared correlation engine reference
incident_correlator = IncidentCorrelationEngine()


def get_unified_timeline(db: Session, correlation_id: str) -> UnifiedTimelineResponse:
    """
    Builds a unified, chronological timeline across all 7 telemetry streams for a given correlation_id.
    Standardizes events into ordered TimelineEventItems (e.g. 09:42 USB inserted -> 09:45 Endpoint isolated).
    """
    timeline_items: List[TimelineEventItem] = []
    seen_ids = set()

    # 1. Query UnifiedTelemetryLog table
    try:
        try:
            corr_uuid = uuid.UUID(correlation_id)
        except ValueError:
            corr_uuid = None

        log_query = db.query(UnifiedTelemetryLog)
        if corr_uuid:
            log_query = log_query.filter(
                or_(
                    UnifiedTelemetryLog.correlation_id == corr_uuid,
                    UnifiedTelemetryLog.correlation_id == str(correlation_id)
                )
            )
        else:
            log_query = log_query.filter(UnifiedTelemetryLog.tenant_id == correlation_id)

        telemetry_logs = log_query.all()
        for log in telemetry_logs:
            item_id = str(log.id)
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)

            ts = log.timestamp or datetime.now(timezone.utc)
            time_formatted = ts.strftime("%H:%M")
            payload = log.payload or {}
            title = payload.get("title") or payload.get("action") or f"{log.category.value} Event ({log.event_type})"

            timeline_items.append(
                TimelineEventItem(
                    event_id=item_id,
                    timestamp=ts,
                    time_formatted=time_formatted,
                    correlation_id=correlation_id,
                    category=log.category.value,
                    title=title,
                    description=payload.get("description") or f"Telemetry log from {log.source}",
                    severity=payload.get("severity", "INFO"),
                    source=log.source,
                    device_id=str(log.device_id) if log.device_id else None,
                    metadata=payload
                )
            )
    except Exception as e:
        logger.warning(f"[TimelineEngine] Telemetry log query note: {e}")

    # 2. Query Threats
    try:
        threat_query = db.query(Threat)
        if corr_uuid:
            threats = threat_query.filter(Threat.id == corr_uuid).all()
        else:
            threats = threat_query.all()

        for threat in threats:
            item_id = f"threat-{threat.id}"
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)

            ts = threat.detected_at or datetime.now(timezone.utc)
            timeline_items.append(
                TimelineEventItem(
                    event_id=item_id,
                    timestamp=ts,
                    time_formatted=ts.strftime("%H:%M"),
                    correlation_id=correlation_id,
                    category="THREAT",
                    title=f"Threat created ({threat.threat_type})",
                    description=threat.description,
                    severity=threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
                    source="Threat Detection Engine",
                    device_id=str(threat.device_id) if threat.device_id else None,
                    metadata={"threat_id": str(threat.id), "status": threat.status}
                )
            )

            # Query associated Alerts
            alerts = db.query(Alert).filter(Alert.threat_id == threat.id).all()
            for alert in alerts:
                alert_item_id = f"alert-{alert.id}"
                if alert_item_id in seen_ids:
                    continue
                seen_ids.add(alert_item_id)

                ats = alert.created_at or datetime.now(timezone.utc)
                timeline_items.append(
                    TimelineEventItem(
                        event_id=alert_item_id,
                        timestamp=ats,
                        time_formatted=ats.strftime("%H:%M"),
                        correlation_id=correlation_id,
                        category="ALERT",
                        title=f"Alert generated: {alert.title}",
                        description=alert.message,
                        severity=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                        source="Alert Engine",
                        device_id=str(alert.device_id) if alert.device_id else None,
                        metadata={"alert_id": str(alert.id), "status": alert.status}
                    )
                )

                # Query associated ResponseActions
                responses = db.query(ResponseAction).filter(ResponseAction.alert_id == alert.id).all()
                for resp in responses:
                    resp_item_id = f"resp-{resp.id}"
                    if resp_item_id in seen_ids:
                        continue
                    seen_ids.add(resp_item_id)

                    rts = resp.executed_at or resp.created_at or datetime.now(timezone.utc)
                    action_title = resp.action_type.value.replace("_", " ").title() if hasattr(resp.action_type, "value") else str(resp.action_type)
                    timeline_items.append(
                        TimelineEventItem(
                            event_id=resp_item_id,
                            timestamp=rts,
                            time_formatted=rts.strftime("%H:%M"),
                            correlation_id=correlation_id,
                            category="RESPONSE",
                            title=f"Response action: {action_title}",
                            description=resp.details,
                            severity="HIGH",
                            source="Automated Response Engine",
                            device_id=str(resp.device_id) if resp.device_id else None,
                            metadata={"response_id": str(resp.id), "status": resp.status}
                        )
                    )
    except Exception as e:
        logger.warning(f"[TimelineEngine] Threat/Alert/Response query note: {e}")

    # 3. Check in-memory Incident Correlation Engine
    try:
        inc_data = incident_correlator.get_incident(correlation_id)
        if inc_data:
            for raw_ev in inc_data.get("raw_events", []):
                ev_id = f"inc-correlator-{raw_ev.get('timestamp')}-{raw_ev.get('rule_name')}"
                if ev_id in seen_ids:
                    continue
                seen_ids.add(ev_id)

                ts_str = raw_ev.get("timestamp")
                try:
                    ev_ts = datetime.fromisoformat(ts_str)
                except Exception:
                    ev_ts = datetime.now(timezone.utc)

                timeline_items.append(
                    TimelineEventItem(
                        event_id=ev_id,
                        timestamp=ev_ts,
                        time_formatted=ev_ts.strftime("%H:%M"),
                        correlation_id=correlation_id,
                        category=raw_ev.get("subsystem", "CORRELATED"),
                        title=raw_ev.get("rule_name") or "Correlated Subsystem Event",
                        description=raw_ev.get("description"),
                        severity=raw_ev.get("severity", "MEDIUM"),
                        source="Incident Correlation Engine",
                        device_id=inc_data.get("device_id"),
                        metadata=raw_ev.get("raw_payload", {})
                    )
                )
    except Exception as e:
        logger.warning(f"[TimelineEngine] Incident correlator lookup note: {e}")

    # Sort all timeline items chronologically (oldest first)
    timeline_items.sort(key=lambda x: x.timestamp)

    start_time = timeline_items[0].timestamp if timeline_items else None
    end_time = timeline_items[-1].timestamp if timeline_items else None

    return UnifiedTimelineResponse(
        correlation_id=correlation_id,
        total_events=len(timeline_items),
        start_time=start_time,
        end_time=end_time,
        timeline=timeline_items
    )


def ingest_correlated_sequence(
    db: Session,
    device_id: uuid.UUID,
    correlation_id: str,
    events: List[SequenceEventItem]
) -> UnifiedTimelineResponse:
    """
    Ingests a complete correlated event sequence sharing the same correlation_id.
    Persists events into telemetry_logs and registers them into IncidentCorrelationEngine.
    """
    corr_uuid = uuid.UUID(correlation_id) if isinstance(correlation_id, str) and len(correlation_id) == 36 else uuid.uuid4()
    corr_str = str(corr_uuid)

    for event in events:
        ts = event.timestamp if event.timestamp else datetime.now(timezone.utc)
        
        cat_str = event.category.upper()
        if cat_str in ["USB", "FILE_INTEGRITY", "PROCESS", "NETWORK"]:
            category_enum = TelemetryCategoryEnum(cat_str)
        else:
            category_enum = TelemetryCategoryEnum.SECURITY_EVENT

        # 1. Create UnifiedTelemetryLog
        log_entry = UnifiedTelemetryLog(
            id=uuid.uuid4(),
            device_id=device_id,
            category=category_enum,
            event_type=event.title,
            source="Timeline Simulation Engine",
            timestamp=ts,
            correlation_id=corr_uuid,
            tenant_id="default_tenant",
            host_info={"device_id": str(device_id)},
            payload={
                "title": event.title,
                "description": event.description or "",
                "severity": event.severity,
                **event.metadata
            }
        )
        db.add(log_entry)

        # 2. Correlate with in-memory Incident Correlation Engine
        incident_correlator.correlate_event(
            device_id=str(device_id),
            subsystem=event.category,
            rule_name=event.title,
            description=event.description or event.title,
            severity=event.severity,
            raw_payload=event.metadata,
            existing_correlation_id=corr_str
        )

    db.commit()
    logger.info(f"[TimelineEngine] Ingested {len(events)} events for correlation_id={corr_str}")

    return get_unified_timeline(db, corr_str)
