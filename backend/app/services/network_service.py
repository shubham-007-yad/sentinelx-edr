from typing import List, Optional, Any, Dict
from uuid import UUID
from sqlalchemy.orm import Session, joinedload
from app.models.network_connection import NetworkConnection
from app.models.process_info import ProcessInfo
from app.models.device import Device
from app.models.threat import Threat
from app.models.alert import Alert
from app.schemas.network import NetworkConnectionCreate
from app.detection.network import NetworkDetectionEngine
from app.services import alert_service

network_detection_engine = NetworkDetectionEngine()


def _evaluate_and_alert_network(
    db: Session,
    device_id: UUID,
    connections_data: List[Any],
    db_connections: Optional[List[NetworkConnection]] = None
):
    """Evaluates network telemetry against Network Detection Engine rules, generates alerts, and links threat_id / alert_id."""
    dicts = []
    for c in connections_data:
        if isinstance(c, dict):
            dicts.append(c)
        elif hasattr(c, "model_dump"):
            dicts.append(c.model_dump())
        elif hasattr(c, "dict"):
            dicts.append(c.dict())

    findings = network_detection_engine.evaluate_connection_batch(dicts)
    for finding in findings:
        alert_obj = alert_service.create_network_alert(
            db=db,
            device_id=device_id,
            rule_name=finding.rule_name,
            threat_type=finding.threat_type,
            severity=finding.severity,
            description=finding.description,
            pid=finding.pid,
            process_name=finding.process_name,
            remote_ip=finding.remote_ip,
            remote_port=finding.remote_port,
            rule_id=finding.rule_id,
            mitre_attack=finding.mitre_attack,
            confidence=finding.confidence
        )

        # Link threat_id & alert_id back to matching NetworkConnection DB object
        if db_connections:
            for conn in db_connections:
                match_pid = (conn.pid == finding.pid) if finding.pid else True
                match_remote = (conn.remote_ip == finding.remote_ip) if finding.remote_ip else True
                if match_pid and match_remote:
                    conn.threat_id = alert_obj.threat_id
                    conn.alert_id = alert_obj.id


def ingest_network_connections(
    db: Session,
    device_id: UUID,
    connections_in: List[NetworkConnectionCreate],
    clear_existing: bool = True
) -> List[NetworkConnection]:
    """
    Ingests a snapshot of active network connection telemetry from an endpoint agent.
    Optionally clears existing connection state records for the target device.
    Correlates network connections with active process inventory records by PID.
    Evaluates network telemetry against Network Detection Engine rules.
    """
    if clear_existing:
        db.query(NetworkConnection).filter(NetworkConnection.device_id == device_id).delete(synchronize_session=False)

    # Fetch existing process inventory for device to correlate process_id by PID
    device_processes = db.query(ProcessInfo).filter(ProcessInfo.device_id == device_id).all()
    pid_to_process_id = {proc.pid: proc.id for proc in device_processes if proc.pid is not None}

    db_connections: List[NetworkConnection] = []

    for conn_data in connections_in:
        process_id = pid_to_process_id.get(conn_data.pid) if conn_data.pid else None

        conn_obj = NetworkConnection(
            device_id=device_id,
            process_id=process_id,
            pid=conn_data.pid,
            process_name=conn_data.process_name,
            executable_path=conn_data.executable_path,
            local_ip=conn_data.local_ip,
            local_port=conn_data.local_port,
            remote_ip=conn_data.remote_ip,
            remote_port=conn_data.remote_port,
            protocol=conn_data.protocol.upper() if conn_data.protocol else "TCP",
            state=conn_data.state.upper() if conn_data.state else "ESTABLISHED",
            bytes_sent=conn_data.bytes_sent or 0,
            bytes_received=conn_data.bytes_received or 0
        )
        db.add(conn_obj)
        db_connections.append(conn_obj)

    # Run Network Detection Engine Evaluation
    _evaluate_and_alert_network(db, device_id, connections_in, db_connections=db_connections)

    db.commit()

    for conn_obj in db_connections:
        db.refresh(conn_obj)

    return db_connections


def get_network_connections(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    device_id: Optional[UUID] = None,
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    protocol: Optional[str] = None,
    state: Optional[str] = None,
    remote_ip: Optional[str] = None
) -> List[NetworkConnection]:
    """
    Retrieves active network connections across managed devices with optional query filtering.
    """
    query = db.query(NetworkConnection)

    if device_id:
        query = query.filter(NetworkConnection.device_id == device_id)
    if pid:
        query = query.filter(NetworkConnection.pid == pid)
    if process_name:
        query = query.filter(NetworkConnection.process_name.ilike(f"%{process_name}%"))
    if protocol:
        query = query.filter(NetworkConnection.protocol == protocol.upper())
    if state:
        query = query.filter(NetworkConnection.state == state.upper())
    if remote_ip:
        query = query.filter(NetworkConnection.remote_ip.ilike(f"%{remote_ip}%"))

    return query.order_by(NetworkConnection.created_at.desc()).offset(skip).limit(limit).all()


def get_device_network_connections(
    db: Session,
    device_id: UUID,
    skip: int = 0,
    limit: int = 100,
    protocol: Optional[str] = None,
    state: Optional[str] = None
) -> List[NetworkConnection]:
    """
    Retrieves network connection inventory specifically for a target device.
    """
    return get_network_connections(
        db=db,
        skip=skip,
        limit=limit,
        device_id=device_id,
        protocol=protocol,
        state=state
    )


def get_correlated_network_connection(
    db: Session,
    connection_id: UUID
) -> Optional[Dict[str, Any]]:
    """
    Retrieves full 360° correlated telemetry pivot for an analyst investigation:
    Links Network Connection ➔ Process Lineage ➔ Endpoint Device ➔ Threat Findings ➔ Alert ➔ Response Actions.
    """
    conn = db.query(NetworkConnection).filter(NetworkConnection.id == connection_id).first()
    if not conn:
        return None

    device = db.query(Device).filter(Device.id == conn.device_id).first()

    # Correlate ProcessInfo
    proc_info = None
    if conn.process_id:
        proc_info = db.query(ProcessInfo).filter(ProcessInfo.id == conn.process_id).first()
    elif conn.pid:
        proc_info = db.query(ProcessInfo).filter(
            ProcessInfo.device_id == conn.device_id,
            ProcessInfo.pid == conn.pid
        ).first()

    # Correlate Threat & Alert
    threat_info = None
    if conn.threat_id:
        threat_info = db.query(Threat).filter(Threat.id == conn.threat_id).first()

    alert_info = None
    if conn.alert_id:
        alert_info = db.query(Alert).filter(Alert.id == conn.alert_id).first()

    return {
        "connection_id": conn.id,
        "device_id": conn.device_id,
        "device_hostname": device.hostname if device else None,
        "device_ip": device.ip_address if device else None,
        "device_status": device.status.value if device and hasattr(device.status, "value") else (str(device.status) if device else None),

        # Process Correlation
        "process_id": proc_info.id if proc_info else conn.process_id,
        "pid": conn.pid,
        "process_name": conn.process_name or (proc_info.name if proc_info else None),
        "executable_path": conn.executable_path or (proc_info.exe_path if proc_info else None),
        "cmdline": proc_info.cmdline if proc_info else None,
        "username": proc_info.username if proc_info else None,
        "ppid": proc_info.ppid if proc_info else None,

        # Socket Telemetry
        "local_ip": conn.local_ip,
        "local_port": conn.local_port,
        "remote_ip": conn.remote_ip,
        "remote_port": conn.remote_port,
        "protocol": conn.protocol,
        "state": conn.state,

        # Threat Correlation
        "threat_id": threat_info.id if threat_info else None,
        "threat_type": threat_info.threat_type.value if threat_info and hasattr(threat_info.threat_type, "value") else (str(threat_info.threat_type) if threat_info else None),
        "threat_severity": threat_info.severity.value if threat_info and hasattr(threat_info.severity, "value") else (str(threat_info.severity) if threat_info else None),
        "rule_name": threat_info.rule_name if threat_info else None,
        "threat_description": threat_info.description if threat_info else None,

        # Alert Correlation
        "alert_id": alert_info.id if alert_info else None,
        "alert_title": alert_info.title if alert_info else None,
        "alert_message": alert_info.message if alert_info else None,
        "alert_severity": alert_info.severity.value if alert_info and hasattr(alert_info.severity, "value") else (str(alert_info.severity) if alert_info else None),
        "alert_status": alert_info.status.value if alert_info and hasattr(alert_info.status, "value") else (str(alert_info.status) if alert_info else None),

        # Pivot Actions
        "available_response_actions": ["TERMINATE_PROCESS", "ISOLATE_DEVICE", "BLOCK_IP"]
    }


def process_live_network_events(
    db: Session,
    device_id: UUID,
    events: Any
) -> dict:
    """
    Processes real-time network connection diff events:
    - connected: Add new active connection record
    - disconnected: Delete closed connection record
    - state_changed: Update connection socket status
    - long_running: Monitor long-lived active sessions
    """
    connected_count = 0
    disconnected_count = 0
    state_changed_count = 0

    # Correlate process IDs
    device_processes = db.query(ProcessInfo).filter(ProcessInfo.device_id == device_id).all()
    pid_to_process_id = {proc.pid: proc.id for proc in device_processes if proc.pid is not None}

    new_db_conns: List[NetworkConnection] = []

    # 1. Handle newly connected sockets
    for conn_data in events.connected:
        process_id = pid_to_process_id.get(conn_data.pid) if conn_data.pid else None
        conn_obj = NetworkConnection(
            device_id=device_id,
            process_id=process_id,
            pid=conn_data.pid,
            process_name=conn_data.process_name,
            executable_path=conn_data.executable_path,
            local_ip=conn_data.local_ip,
            local_port=conn_data.local_port,
            remote_ip=conn_data.remote_ip,
            remote_port=conn_data.remote_port,
            protocol=(conn_data.protocol or "TCP").upper(),
            state=(conn_data.state or "ESTABLISHED").upper(),
            bytes_sent=conn_data.bytes_sent or 0,
            bytes_received=conn_data.bytes_received or 0
        )
        db.add(conn_obj)
        new_db_conns.append(conn_obj)
        connected_count += 1

    if events.connected:
        _evaluate_and_alert_network(db, device_id, events.connected, db_connections=new_db_conns)

    # 2. Handle disconnected sockets
    for conn_data in events.disconnected:
        query = db.query(NetworkConnection).filter(
            NetworkConnection.device_id == device_id,
            NetworkConnection.protocol == (conn_data.protocol or "TCP").upper()
        )
        if conn_data.pid is not None:
            query = query.filter(NetworkConnection.pid == conn_data.pid)
        if conn_data.local_port is not None:
            query = query.filter(NetworkConnection.local_port == conn_data.local_port)
        if conn_data.remote_ip is not None:
            query = query.filter(NetworkConnection.remote_ip == conn_data.remote_ip)

        deleted = query.delete(synchronize_session=False)
        disconnected_count += 1

    # 3. Handle state changed sockets
    for state_item in events.state_changed:
        conn_data = state_item.connection
        new_state = state_item.new_state
        db_conn = db.query(NetworkConnection).filter(
            NetworkConnection.device_id == device_id,
            NetworkConnection.protocol == (conn_data.protocol or "TCP").upper(),
            NetworkConnection.local_port == conn_data.local_port
        ).first()

        if db_conn:
            db_conn.state = new_state.upper()
            state_changed_count += 1

    db.commit()

    return {
        "message": "Live network events processed successfully",
        "connected_count": connected_count,
        "disconnected_count": disconnected_count,
        "state_changed_count": state_changed_count,
        "long_running_count": len(events.long_running),
        "total_active": events.total_active
    }


def get_connection_timeline(
    db: Session,
    connection_id: UUID
) -> Optional[Dict[str, Any]]:
    """
    Constructs a chronological investigation timeline for a target network connection event chain:
    1. Process Started
    2. Network Connection Established
    3. Data Volume Transferred
    4. C2 Beacon / Threat Finding Detected
    5. Incident Alert Generated
    6. Response Action Executed (Blocked by analyst)
    """
    conn = db.query(NetworkConnection).filter(NetworkConnection.id == connection_id).first()
    if not conn:
        return None

    timeline = []

    # 1. Process Event (e.g. powershell.exe started)
    proc_info = None
    if conn.process_id:
        proc_info = db.query(ProcessInfo).filter(ProcessInfo.id == conn.process_id).first()
    elif conn.pid:
        proc_info = db.query(ProcessInfo).filter(
            ProcessInfo.device_id == conn.device_id,
            ProcessInfo.pid == conn.pid
        ).first()

    proc_name = conn.process_name or (proc_info.name if proc_info else "Process")
    proc_time = conn.created_at
    timeline.append({
        "timestamp": proc_time,
        "time_formatted": proc_time.strftime("%H:%M"),
        "event_type": "PROCESS_STARTED",
        "title": f"{proc_name} started",
        "description": f"Process execution initiated on host (PID {conn.pid or 'N/A'})",
        "severity": "INFO",
        "icon": "⚡",
        "metadata": {"pid": conn.pid, "process_name": proc_name, "exe_path": conn.executable_path}
    })

    # 2. Connection Event (Connected to remote IP)
    conn_time = conn.created_at
    remote_target = f"{conn.remote_ip}:{conn.remote_port}" if conn.remote_ip else "remote socket"
    timeline.append({
        "timestamp": conn_time,
        "time_formatted": conn_time.strftime("%H:%M"),
        "event_type": "NETWORK_CONNECTED",
        "title": f"Connected to {conn.remote_ip or 'remote host'}",
        "description": f"Outbound {conn.protocol} connection established to {remote_target}",
        "severity": "INFO",
        "icon": "🌐",
        "metadata": {"remote_ip": conn.remote_ip, "remote_port": conn.remote_port, "protocol": conn.protocol}
    })

    # 3. Data Transfer Event (Transferred MB)
    total_bytes = (conn.bytes_sent or 0) + (conn.bytes_received or 0)
    bytes_formatted = f"{(total_bytes / (1024*1024)):.1f} MB" if total_bytes >= 1024*1024 else (f"{total_bytes // 1024} KB" if total_bytes >= 1024 else f"{total_bytes} B")
    timeline.append({
        "timestamp": conn.updated_at or conn.created_at,
        "time_formatted": (conn.updated_at or conn.created_at).strftime("%H:%M"),
        "event_type": "DATA_TRANSFERRED",
        "title": f"Transferred {bytes_formatted}",
        "description": f"Cumulative network throughput: {conn.bytes_sent} bytes sent, {conn.bytes_received} bytes received",
        "severity": "LOW",
        "icon": "📊",
        "metadata": {"bytes_sent": conn.bytes_sent, "bytes_received": conn.bytes_received}
    })

    # 4. Threat Finding / Beacon Detection
    threat_info = None
    if conn.threat_id:
        threat_info = db.query(Threat).filter(Threat.id == conn.threat_id).first()

    if threat_info:
        title = "Beacon detected" if "BEACON" in str(threat_info.threat_type) else f"Threat detected: {threat_info.rule_name}"
        t_time = threat_info.detected_at or conn.created_at
        timeline.append({
            "timestamp": t_time,
            "time_formatted": t_time.strftime("%H:%M"),
            "event_type": "BEACON_DETECTED",
            "title": title,
            "description": threat_info.description or "Behavioral threat rule triggered on network socket",
            "severity": threat_info.severity.value if hasattr(threat_info.severity, "value") else str(threat_info.severity),
            "icon": "🚨",
            "metadata": {"threat_id": str(threat_info.id), "threat_type": str(threat_info.threat_type)}
        })

    # 5. Alert Generation
    alert_info = None
    if conn.alert_id:
        alert_info = db.query(Alert).filter(Alert.id == conn.alert_id).first()

    if alert_info:
        timeline.append({
            "timestamp": alert_info.created_at,
            "time_formatted": alert_info.created_at.strftime("%H:%M"),
            "event_type": "ALERT_GENERATED",
            "title": "Alert generated",
            "description": f"Incident Alert: '{alert_info.title}' (Severity: {alert_info.severity})",
            "severity": alert_info.severity.value if hasattr(alert_info.severity, "value") else str(alert_info.severity),
            "icon": "🔔",
            "metadata": {"alert_id": str(alert_info.id), "title": alert_info.title}
        })

    # 6. Response Action (Blocked by analyst)
    from app.models.response_action import ResponseAction
    actions = db.query(ResponseAction).filter(ResponseAction.device_id == conn.device_id).all()
    if conn.alert_id:
        alert_actions = [a for a in actions if a.alert_id == conn.alert_id]
        if alert_actions:
            actions = alert_actions

    if actions:
        latest_action = max(actions, key=lambda a: a.started_at)
        act_type_str = str(latest_action.action_type.value) if hasattr(latest_action.action_type, "value") else str(latest_action.action_type)
        act_title = "Blocked by analyst" if any(kw in act_type_str for kw in ["BLOCK", "KILL", "TERMINATE", "ISOLATE"]) else f"Action {act_type_str} executed"
        timeline.append({
            "timestamp": latest_action.completed_at or latest_action.started_at,
            "time_formatted": (latest_action.completed_at or latest_action.started_at).strftime("%H:%M"),
            "event_type": "RESPONSE_EXECUTED",
            "title": act_title,
            "description": f"Response action '{act_type_str}' initiated by {latest_action.initiated_by} (Status: {latest_action.status})",
            "severity": "CRITICAL",
            "icon": "🛑",
            "metadata": {"action_id": str(latest_action.id), "action_type": act_type_str}
        })

    return {
        "connection_id": conn.id,
        "device_id": conn.device_id,
        "timeline": timeline
    }
