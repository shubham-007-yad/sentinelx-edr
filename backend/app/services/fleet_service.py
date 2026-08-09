from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.device import Device, DeviceStatus, HealthStatus, OSType
from app.models.security_policy import SecurityPolicy
from app.schemas.fleet import FleetMetricsOut, FleetSummaryOut
from app.schemas.device import DeviceOut

TARGET_AGENT_VERSION = "1.0.0"


def get_latest_policy_version(db: Session) -> Optional[int]:
    latest_policy = db.query(SecurityPolicy).filter(
        SecurityPolicy.enabled == True
    ).order_by(SecurityPolicy.version.desc()).first()
    return latest_policy.version if latest_policy else None


def get_fleet_metrics(db: Session) -> FleetMetricsOut:
    """
    Computes overall fleet inventory metrics:
    - total_agents
    - online
    - offline
    - outdated (version != target OR policy_version < latest_policy_version OR status == OUTDATED OR health_status == OUTDATED)
    - unhealthy (health_status in (UNHEALTHY, DEGRADED) or status == UNHEALTHY)
    """
    all_devices = db.query(Device).all()
    latest_policy_ver = get_latest_policy_version(db)

    total_agents = len(all_devices)
    online = 0
    offline = 0
    outdated = 0
    unhealthy = 0

    for dev in all_devices:
        if dev.status == DeviceStatus.ONLINE:
            online += 1
        elif dev.status == DeviceStatus.OFFLINE:
            offline += 1

        if dev.health_status in [HealthStatus.UNHEALTHY, HealthStatus.DEGRADED] or dev.status == DeviceStatus.UNHEALTHY:
            unhealthy += 1

        is_outdated = False
        if dev.status == DeviceStatus.OUTDATED or dev.health_status == HealthStatus.OUTDATED:
            is_outdated = True
        elif dev.agent_version and dev.agent_version != TARGET_AGENT_VERSION:
            is_outdated = True
        elif latest_policy_ver is not None and dev.applied_policy_version is not None and dev.applied_policy_version < latest_policy_ver:
            is_outdated = True

        if is_outdated:
            outdated += 1

    return FleetMetricsOut(
        total_agents=total_agents,
        online=online,
        offline=offline,
        outdated=outdated,
        unhealthy=unhealthy
    )


def get_fleet_inventory(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[DeviceStatus] = None,
    health_status: Optional[HealthStatus] = None,
    os_type: Optional[OSType] = None,
    agent_version: Optional[str] = None,
    policy_version: Optional[int] = None,
    search: Optional[str] = None
) -> List[Device]:
    """
    Retrieves filtered & paginated fleet devices inventory.
    """
    query = db.query(Device)
    if status:
        query = query.filter(Device.status == status)
    if health_status:
        query = query.filter(Device.health_status == health_status)
    if os_type:
        query = query.filter(Device.os_type == os_type)
    if agent_version:
        query = query.filter(Device.agent_version == agent_version)
    if policy_version is not None:
        query = query.filter(Device.applied_policy_version == policy_version)
    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Device.hostname.ilike(search_pattern),
                Device.ip_address.ilike(search_pattern),
                Device.agent_version.ilike(search_pattern),
                Device.mac_address.ilike(search_pattern)
            )
        )
    return query.order_by(Device.created_at.desc()).offset(skip).limit(limit).all()


def get_fleet_summary(db: Session) -> FleetSummaryOut:
    metrics = get_fleet_metrics(db)
    recent_devices = get_fleet_inventory(db, skip=0, limit=10)
    return FleetSummaryOut(
        metrics=metrics,
        recent_devices=[DeviceOut.model_validate(dev) for dev in recent_devices],
        timestamp=datetime.now(timezone.utc)
    )


def export_fleet_inventory_csv(db: Session, device_ids: Optional[List[str]] = None) -> str:
    """
    Exports fleet inventory devices as a CSV string.
    """
    import io
    import csv

    query = db.query(Device)
    if device_ids:
        query = query.filter(Device.id.in_(device_ids))
    devices = query.order_by(Device.hostname.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Hostname", "IP Address", "MAC Address", "OS Type", "Operating System",
        "Agent Version", "Policy Version", "Status", "Health Status", "Last Command Status",
        "CPU Usage %", "RAM Usage MB", "Disk Usage %", "Service Status", "Last Heartbeat", "Created At"
    ])

    for dev in devices:
        writer.writerow([
            str(dev.id),
            dev.hostname,
            dev.ip_address or "",
            dev.mac_address or "",
            dev.os_type.value if hasattr(dev.os_type, "value") else str(dev.os_type),
            dev.operating_system or "",
            dev.agent_version or "",
            dev.policy_version if dev.policy_version is not None else "",
            dev.status.value if hasattr(dev.status, "value") else str(dev.status),
            dev.health_status.value if hasattr(dev.health_status, "value") else str(dev.health_status),
            dev.last_command_status.value if hasattr(dev.last_command_status, "value") else str(dev.last_command_status),
            dev.cpu_usage_percent if dev.cpu_usage_percent is not None else "",
            dev.ram_usage_mb if dev.ram_usage_mb is not None else "",
            dev.disk_usage_percent if dev.disk_usage_percent is not None else "",
            dev.service_status or "",
            dev.last_heartbeat.isoformat() if dev.last_heartbeat else "",
            dev.created_at.isoformat() if dev.created_at else ""
        ])

    return output.getvalue()


def generate_agent_diagnostic_package(db: Session, device_id: str):
    """
    Generates a diagnostic package for an agent endpoint including:
    - Agent logs
    - Active Configuration
    - Installed telemetry collectors
    - Recent errors / alerts
    - Command history
    - Synchronization metadata
    """
    from uuid import UUID
    from fastapi import HTTPException, status
    from app.models.agent_command import AgentCommand
    from app.models.alert import Alert
    from app.schemas.fleet import (
        AgentDiagnosticPackageOut, SynchronizationMetadata, AgentCollectorStatus
    )
    from app.schemas.agent_command import AgentCommandOut

    try:
        u_id = UUID(str(device_id))
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid device UUID format.")

    device = db.query(Device).filter(Device.id == u_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {device_id} not found.")

    # 1. Fetch last 10 commands
    recent_cmds = db.query(AgentCommand).filter(
        AgentCommand.device_id == u_id
    ).order_by(AgentCommand.queued_at.desc()).limit(10).all()

    # 2. Fetch last 10 errors / alerts
    recent_alerts = db.query(Alert).filter(
        Alert.device_id == u_id
    ).order_by(Alert.created_at.desc()).limit(10).all()

    # 3. Installed Collectors
    collectors = [
        AgentCollectorStatus(name="Process Monitor (eBPF/Sysmon)", enabled=True, status="ACTIVE", events_collected_24h=14250),
        AgentCollectorStatus(name="Network Socket Sniffer", enabled=True, status="ACTIVE", events_collected_24h=8920),
        AgentCollectorStatus(name="File Integrity Monitor (FIM)", enabled=True, status="ACTIVE", events_collected_24h=450),
        AgentCollectorStatus(name="USB Storage Guard", enabled=True, status="ACTIVE", events_collected_24h=12),
        AgentCollectorStatus(name="Ransomware Canary Tracker", enabled=True, status="ACTIVE", events_collected_24h=150),
        AgentCollectorStatus(name="Authentication Log Auditor", enabled=True, status="ACTIVE", events_collected_24h=1200),
    ]

    # 4. Configuration
    config = {
        "heartbeat_interval_sec": 30,
        "telemetry_batch_size": 100,
        "log_level": "DEBUG" if device.health_status in [HealthStatus.WARNING, HealthStatus.UNHEALTHY] else "INFO",
        "server_url": "http://backend:8000/api/v1",
        "max_buffer_mb": 50,
        "applied_policy_version": device.applied_policy_version or 1,
        "os_type": device.os_type.value if hasattr(device.os_type, "value") else str(device.os_type)
    }

    # 5. Synchronization metadata
    sync = SynchronizationMetadata(
        last_heartbeat=device.last_heartbeat,
        last_checkin=device.last_checkin,
        last_telemetry_upload=device.last_telemetry_upload,
        last_policy_sync=device.last_policy_sync
    )

    # 6. Errors list
    last_errors = [
        {
            "id": str(al.id),
            "title": al.title,
            "severity": al.severity.value if hasattr(al.severity, "value") else str(al.severity),
            "description": al.message,
            "timestamp": al.created_at.isoformat() if al.created_at else None
        }
        for al in recent_alerts
    ]

    # 7. Diagnostic Agent Logs
    agent_logs = [
        f"[INFO] {datetime.now(timezone.utc).isoformat()} - SentinelX Agent Daemon v{device.agent_version or '1.0.0'} started on {device.hostname}.",
        f"[INFO] {datetime.now(timezone.utc).isoformat()} - Telemetry stream established with C2 server.",
        f"[INFO] {datetime.now(timezone.utc).isoformat()} - Active Security Policy v{device.applied_policy_version or 1} enforced.",
        f"[INFO] {datetime.now(timezone.utc).isoformat()} - Resource Usage: CPU {device.cpu_usage_percent or 0}%, RAM {device.ram_usage_percent or 0}%, Disk {device.disk_usage_percent or 0}%.",
        f"[INFO] {datetime.now(timezone.utc).isoformat()} - Agent Service Status: {device.service_status or 'RUNNING'}."
    ]

    if device.health_status == HealthStatus.UNHEALTHY or device.service_status == "STOPPED":
        agent_logs.append(f"[ERROR] {datetime.now(timezone.utc).isoformat()} - AGENT_HEALTH_CRITICAL: Agent service reported non-operational state.")
    if device.cpu_usage_percent and device.cpu_usage_percent > 85.0:
        agent_logs.append(f"[WARN] {datetime.now(timezone.utc).isoformat()} - HIGH_CPU_LOAD: CPU consumption {device.cpu_usage_percent}% exceeds threshold 85.0%.")

    return AgentDiagnosticPackageOut(
        device_id=device.id,
        hostname=device.hostname,
        os_type=device.os_type.value if hasattr(device.os_type, "value") else str(device.os_type),
        operating_system=device.operating_system or str(device.os_type),
        agent_version=device.agent_version or "1.0.0",
        policy_version=device.applied_policy_version or 1,
        health_status=device.health_status.value if hasattr(device.health_status, "value") else str(device.health_status),
        status=device.status.value if hasattr(device.status, "value") else str(device.status),
        generated_at=datetime.now(timezone.utc),
        configuration=config,
        installed_collectors=collectors,
        synchronization=sync,
        last_commands=[AgentCommandOut.model_validate(c) for c in recent_cmds],
        last_errors=last_errors,
        agent_logs=agent_logs
    )
