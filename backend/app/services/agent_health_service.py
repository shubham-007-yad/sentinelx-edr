import logging
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models.device import Device, DeviceStatus, HealthStatus, CommandStatus
from app.models.threat import Threat, ThreatType, ThreatSeverity
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.schemas.device import AgentHealthReportRequest
from app.core.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)

CPU_THRESHOLD_PERCENT = 85.0
RAM_THRESHOLD_PERCENT = 90.0
DISK_THRESHOLD_PERCENT = 90.0
HEARTBEAT_TIMEOUT_SECONDS = 300  # 5 minutes
POLICY_SYNC_TIMEOUT_SECONDS = 86400  # 24 hours


def _create_health_threat_and_alert(
    db: Session,
    device: Device,
    rule_name: str,
    severity: AlertSeverity,
    title: str,
    message: str
) -> Optional[Alert]:
    """
    Creates a Threat and an Alert entry for an Agent Health Issue.
    Deduplicates alerts by checking if an unread/unacknowledged health alert of the same title exists for the device within the last 15 minutes.
    """
    fifteen_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=15)
    existing = db.query(Alert).filter(
        Alert.device_id == device.id,
        Alert.title == title,
        Alert.created_at >= fifteen_mins_ago
    ).first()

    if existing:
        return existing

    sev_str = severity.value
    threat_sev = ThreatSeverity(sev_str)

    # 1. Create Threat record
    threat = Threat(
        scan_result_id=None,
        threat_type=ThreatType.AGENT_HEALTH_ISSUE,
        severity=threat_sev,
        rule_name=rule_name,
        description=f"[Agent Health Monitor] {message}"
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)

    # 2. Create Alert record
    alert = Alert(
        threat_id=threat.id,
        device_id=device.id,
        title=title,
        message=message,
        severity=severity,
        status=AlertStatus.UNREAD
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # 3. Broadcast Alert via WebSocket
    try:
        alert_payload = {
            "id": str(alert.id),
            "threat_id": str(threat.id),
            "device_id": str(device.id),
            "device": device.hostname,
            "file": "Agent Service",
            "title": alert.title,
            "message": alert.message,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "created_at": alert.created_at.isoformat() if alert.created_at else datetime.now(timezone.utc).isoformat(),
            "time": alert.created_at.isoformat() if alert.created_at else datetime.now(timezone.utc).isoformat(),
        }
        websocket_manager.broadcast_alert_sync(alert_payload)
    except Exception as ws_err:
        logger.warning(f"Failed to broadcast health alert over WebSocket: {ws_err}")

    return alert


def evaluate_device_health(db: Session, device: Device) -> List[Alert]:
    """
    Evaluates operational health conditions for a given device and generates health alerts:
    1. Agent Stopped (service_status in STOPPED, ERROR, CRASHED, FAILED)
    2. No Heartbeat (last_heartbeat > 5 mins ago)
    3. High Resource Usage (CPU > 85%, RAM > 90%, Disk > 90%)
    4. Policy Sync Failure (last_policy_sync > 24 hours ago)
    """
    alerts_generated: List[Alert] = []
    now = datetime.now(timezone.utc)
    is_unhealthy = False
    is_warning = False

    # Rule 1: Agent Stopped
    if device.service_status and device.service_status.upper() in ["STOPPED", "ERROR", "CRASHED", "FAILED"]:
        is_unhealthy = True
        alert = _create_health_threat_and_alert(
            db=db,
            device=device,
            rule_name="AgentServiceStoppedRule",
            severity=AlertSeverity.CRITICAL,
            title=f"Agent Service Stopped on {device.hostname}",
            message=f"SentinelX Agent service status is '{device.service_status}' on host {device.hostname} ({device.ip_address or 'No IP'})."
        )
        if alert:
            alerts_generated.append(alert)

    # Rule 2: No Heartbeat Timeout
    if device.last_heartbeat:
        last_hb = device.last_heartbeat
        if last_hb.tzinfo is None:
            last_hb = last_hb.replace(tzinfo=timezone.utc)
        elapsed_hb = (now - last_hb).total_seconds()
        if elapsed_hb > HEARTBEAT_TIMEOUT_SECONDS:
            is_unhealthy = True
            if device.status == DeviceStatus.ONLINE:
                device.status = DeviceStatus.OFFLINE

            alert = _create_health_threat_and_alert(
                db=db,
                device=device,
                rule_name="NoHeartbeatRule",
                severity=AlertSeverity.HIGH,
                title=f"No Heartbeat Received from {device.hostname}",
                message=f"No heartbeat ping received from agent {device.hostname} for {int(elapsed_hb)} seconds (threshold: {HEARTBEAT_TIMEOUT_SECONDS}s)."
            )
            if alert:
                alerts_generated.append(alert)

    # Rule 3: High Resource Usage
    high_resources = []
    if device.cpu_usage_percent and device.cpu_usage_percent > CPU_THRESHOLD_PERCENT:
        high_resources.append(f"CPU: {device.cpu_usage_percent:.1f}% (threshold: {CPU_THRESHOLD_PERCENT}%)")
    if device.ram_usage_percent and device.ram_usage_percent > RAM_THRESHOLD_PERCENT:
        high_resources.append(f"RAM: {device.ram_usage_percent:.1f}% ({device.ram_usage_mb or 0:.0f} MB, threshold: {RAM_THRESHOLD_PERCENT}%)")
    if device.disk_usage_percent and device.disk_usage_percent > DISK_THRESHOLD_PERCENT:
        high_resources.append(f"Disk: {device.disk_usage_percent:.1f}% (threshold: {DISK_THRESHOLD_PERCENT}%)")

    if high_resources:
        is_warning = True
        resource_msg = ", ".join(high_resources)
        alert = _create_health_threat_and_alert(
            db=db,
            device=device,
            rule_name="HighResourceUsageRule",
            severity=AlertSeverity.HIGH,
            title=f"High Resource Usage on {device.hostname}",
            message=f"Agent endpoint {device.hostname} exceeded resource limits: {resource_msg}."
        )
        if alert:
            alerts_generated.append(alert)

    # Rule 4: Policy Sync Failure
    if device.last_policy_sync:
        last_sync = device.last_policy_sync
        if last_sync.tzinfo is None:
            last_sync = last_sync.replace(tzinfo=timezone.utc)
        elapsed_sync = (now - last_sync).total_seconds()
        if elapsed_sync > POLICY_SYNC_TIMEOUT_SECONDS:
            is_warning = True
            alert = _create_health_threat_and_alert(
                db=db,
                device=device,
                rule_name="PolicySyncFailureRule",
                severity=AlertSeverity.MEDIUM,
                title=f"Policy Sync Failure on {device.hostname}",
                message=f"Agent on {device.hostname} has not synchronized security policy for {int(elapsed_sync / 3600)} hours (threshold: 24h)."
            )
            if alert:
                alerts_generated.append(alert)

    # Set overall health status
    if is_unhealthy:
        device.health_status = HealthStatus.UNHEALTHY
    elif is_warning:
        device.health_status = HealthStatus.WARNING
    else:
        device.health_status = HealthStatus.HEALTHY

    db.add(device)
    db.commit()
    db.refresh(device)
    return alerts_generated


def ingest_agent_health_report(db: Session, report: AgentHealthReportRequest) -> Device:
    """
    Ingests live health telemetry from an agent, updates device operational metrics, runs health evaluation rules, and persists state.
    """
    device = db.query(Device).filter(Device.id == report.device_id).first()
    if not device:
        raise ValueError(f"Device with ID '{report.device_id}' was not found.")

    now = datetime.now(timezone.utc)
    device.cpu_usage_percent = report.cpu_usage_percent
    device.ram_usage_mb = report.ram_usage_mb
    device.ram_usage_percent = report.ram_usage_percent
    device.disk_usage_percent = report.disk_usage_percent
    device.agent_uptime_seconds = report.agent_uptime_seconds
    device.service_status = report.service_status or "RUNNING"

    if report.last_telemetry_upload:
        device.last_telemetry_upload = report.last_telemetry_upload
    else:
        device.last_telemetry_upload = now

    if report.last_policy_sync:
        device.last_policy_sync = report.last_policy_sync

    if report.policy_version is not None:
        device.applied_policy_version = report.policy_version

    if report.agent_version:
        device.agent_version = report.agent_version

    device.last_seen = now
    device.last_heartbeat = now
    device.last_checkin = now
    device.updated_at = now

    # Run health evaluation
    evaluate_device_health(db, device)

    return device


def evaluate_all_fleet_health(db: Session) -> Dict[str, Any]:
    """
    Scans all registered fleet devices and runs health evaluation rules (e.g. heartbeat timeout detection).
    """
    devices = db.query(Device).filter(Device.is_active == True).all()
    evaluated_count = len(devices)
    total_alerts = 0

    for dev in devices:
        alerts = evaluate_device_health(db, dev)
        total_alerts += len(alerts)

    return {
        "evaluated_devices": evaluated_count,
        "health_alerts_generated": total_alerts,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
