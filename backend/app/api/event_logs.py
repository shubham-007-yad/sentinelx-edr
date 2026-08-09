import uuid
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.device import Device
from app.services import event_log_service
import sys
import os

agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../agent"))
if agent_dir not in sys.path:
    sys.path.insert(0, agent_dir)

try:
    from collectors.event_log_collector import EventLogCollector
except ImportError:
    try:
        from agent.collectors.event_log_collector import EventLogCollector
    except ImportError:
        EventLogCollector = None



router = APIRouter(prefix="/events", tags=["OS Event & Auth Logs"])


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
def ingest_events(
    payload: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Ingests OS security event telemetry from an agent endpoint.
    Payload format: { "device_id": "<uuid>", "events": [ { ... } ] }
    """
    device_id_str = payload.get("device_id")
    events = payload.get("events", [])

    if not device_id_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required 'device_id' field in ingestion payload."
        )

    try:
        dev_uuid = uuid.UUID(device_id_str)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid device_id format: '{device_id_str}'"
        )

    result = event_log_service.ingest_security_events(
        db=db,
        device_id=dev_uuid,
        raw_events=events
    )
    return result


@router.get("", status_code=status.HTTP_200_OK)
def list_events(
    device_id: Optional[str] = Query(None, description="Filter by Device UUID"),
    event_type: Optional[str] = Query(None, description="Filter by Event Type"),
    level: Optional[str] = Query(None, description="Filter by Event Level"),
    username: Optional[str] = Query(None, description="Filter by Username"),
    search: Optional[str] = Query(None, description="Search description, user, IP, or computer"),
    date_range: Optional[str] = Query(None, description="Date filter (today, last_24h, last_7d)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Retrieves filtered and paginated OS security & authentication event logs.
    """
    dev_uuid = None
    if device_id:
        try:
            dev_uuid = uuid.UUID(device_id)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid device_id format: '{device_id}'"
            )

    return event_log_service.get_security_events(
        db=db,
        device_id=dev_uuid,
        event_type=event_type,
        level=level,
        username=username,
        search=search,
        date_range=date_range,
        skip=skip,
        limit=limit
    )



@router.get("/summary", status_code=status.HTTP_200_OK)
def get_summary(
    device_id: Optional[str] = Query(None, description="Filter summary by Device UUID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Returns aggregate authentication and security event metrics for dashboard cards.
    """
    dev_uuid = None
    if device_id:
        try:
            dev_uuid = uuid.UUID(device_id)
        except Exception:
            pass

    return event_log_service.get_authentication_summary(db=db, device_id=dev_uuid)


@router.get("/auth-timeline", status_code=status.HTTP_200_OK)
def get_timeline(
    device_id: Optional[str] = Query(None, description="Filter timeline by Device UUID"),
    limit: int = Query(30, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Returns a chronological sequence of authentication, logon, and privilege events.
    """
    dev_uuid = None
    if device_id:
        try:
            dev_uuid = uuid.UUID(device_id)
        except Exception:
            pass

    return event_log_service.get_auth_timeline(db=db, device_id=dev_uuid, limit=limit)


@router.get("/attack-chain", status_code=status.HTTP_200_OK)
def get_attack_chain(
    device_id: Optional[str] = Query(None, description="Filter attack chain by Device UUID"),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Phase 7: Returns step-by-step Attack Chain timeline.
    Sequence: 02:10 Failed Login ➔ 02:10 Failed Login ➔ 02:11 Administrator Login ➔ 02:12 New Scheduled Task ➔ Critical Alert
    """
    dev_uuid = None
    if device_id:
        try:
            dev_uuid = uuid.UUID(device_id)
        except Exception:
            pass

    return event_log_service.get_attack_chain_timeline(db=db, device_id=dev_uuid, limit=limit)



@router.post("/simulate", status_code=status.HTTP_200_OK)
def trigger_simulation(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Fires realistic security event simulations for SOC testing and UI demo.
    Scenarios: BRUTE_FORCE, PRIVILEGE_ESCALATION, ACCOUNT_DISABLED, OFF_HOURS, PERSISTENCE, LOG_CLEARING
    """
    scenario = payload.get("scenario", "BRUTE_FORCE").upper()
    device_id_str = payload.get("device_id")

    if device_id_str:
        try:
            dev_uuid = uuid.UUID(device_id_str)
        except Exception:
            dev_uuid = None
    else:
        # Default to first online device
        dev = db.query(Device).first()
        dev_uuid = dev.id if dev else None

    if not dev_uuid:
        dev = Device(hostname="sentinelx-sim-node", os_version="Linux/Windows Sim")
        db.add(dev)
        db.commit()
        db.refresh(dev)
        dev_uuid = dev.id

    if scenario == "ATTACK_CHAIN":
        return event_log_service.trigger_attack_chain_sequence(db=db, device_id=dev_uuid)

    if scenario == "BRUTE_FORCE":

        # Generate 5 rapid failed logons followed by 1 logon attempt
        ts_now = datetime.now().isoformat()
        for i in range(5):
            sim_events.append({
                "id": str(uuid.uuid4()),
                "device_id": str(dev_uuid),
                "event_source": "Security",
                "event_id": "4625",
                "event_type": "AUTHENTICATION_FAILURE",
                "level": "Warning",
                "username": "admin_target",
                "computer": "CORP-DC01",
                "logon_type": "10-RemoteDesktop",
                "ip_address": "198.51.100.44",
                "status": "FAILED",
                "description": f"Failed logon attempt #{i+1} for admin_target from IP 198.51.100.44",
                "timestamp": ts_now
            })
    elif scenario == "PRIVILEGE_ESCALATION":
        sim_events.append({
            "id": str(uuid.uuid4()),
            "device_id": str(dev_uuid),
            "event_source": "Security",
            "event_id": "4732",
            "event_type": "PRIVILEGE_ESCALATION",
            "level": "Warning",
            "username": "backdoor_admin",
            "computer": "CORP-FILE01",
            "status": "SUCCESS",
            "description": "User backdoor_admin added to Administrators security-enabled group by SYSTEM",
            "timestamp": datetime.now().isoformat()
        })
    elif scenario == "ACCOUNT_DISABLED":
        sim_events.append({
            "id": str(uuid.uuid4()),
            "device_id": str(dev_uuid),
            "event_source": "Security",
            "event_id": "4725",
            "event_type": "ACCOUNT_MANAGEMENT",
            "level": "Warning",
            "username": "compromised_user",
            "computer": "CORP-WORKSTATION",
            "status": "SUCCESS",
            "description": "User account compromised_user was disabled by Security Admin",
            "timestamp": datetime.now().isoformat()
        })
    elif scenario == "OFF_HOURS":
        sim_events.append({
            "id": str(uuid.uuid4()),
            "device_id": str(dev_uuid),
            "event_source": "Security",
            "event_id": "4624",
            "event_type": "AUTHENTICATION_SUCCESS",
            "level": "Information",
            "username": "night_owl",
            "computer": "FINANCE-PC",
            "logon_type": "2-Interactive",
            "ip_address": "10.0.0.99",
            "status": "SUCCESS",
            "description": "User night_owl logged in interactively at 03:15 AM off-hours",
            "timestamp": "2026-08-02T03:15:00Z"
        })
    elif scenario == "PERSISTENCE":
        sim_events.append({
            "id": str(uuid.uuid4()),
            "device_id": str(dev_uuid),
            "event_source": "Security",
            "event_id": "4697",
            "event_type": "PERSISTENCE",
            "level": "Warning",
            "username": "SYSTEM",
            "computer": "CORP-SRV01",
            "status": "SUCCESS",
            "description": "A service was installed in the system: MalwarePersistenceSvc (Path: C:\\Windows\\temp\\svc.exe)",
            "timestamp": datetime.now().isoformat()
        })
    elif scenario == "LOG_CLEARING":
        sim_events.append({
            "id": str(uuid.uuid4()),
            "device_id": str(dev_uuid),
            "event_source": "Security",
            "event_id": "1102",
            "event_type": "DEFENSE_EVASION",
            "level": "Critical",
            "username": "Administrator",
            "computer": "CORP-DC01",
            "status": "SUCCESS",
            "description": "CRITICAL: The Windows Security Audit Log was cleared by Administrator",
            "timestamp": datetime.now().isoformat()
        })
    else:
        sim_events = collector._generate_windows_sample_events(limit=5)

    res = event_log_service.ingest_security_events(db=db, device_id=dev_uuid, raw_events=sim_events)
    return {
        "status": "SIMULATED",
        "scenario": scenario,
        "device_id": str(dev_uuid),
        "events_injected": len(sim_events),
        "ingest_result": res
    }


@router.post("/action", status_code=status.HTTP_200_OK)
def execute_event_response_action(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Phase 6: Response Actions for OS Security & Auth Events.
    Actions supported:
    - DISABLE_USER: Disables user account (simulation)
    - FORCE_LOGOUT: Forcefully logs out user session (simulation)
    - INVESTIGATE: Flags event for SOC investigation
    - IGNORE: Marks event as ignored false positive
    - ALLOWLIST: Allowlists user / IP / event
    Every action is audited in ResponseAuditLog!
    """
    from app.services import response_service
    from app.models.response_action import ResponseActionType

    action_type_str = str(payload.get("action_type", "")).upper()
    device_id_str = payload.get("device_id")
    username = payload.get("username")
    event_id = payload.get("event_id")

    if not device_id_str:
        # Find default online device if not supplied
        dev = db.query(Device).first()
        if not dev:
            raise HTTPException(status_code=400, detail="No active device found for response action.")
        dev_uuid = dev.id
    else:
        try:
            dev_uuid = uuid.UUID(device_id_str)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid device_id format: '{device_id_str}'")

    action_type_map = {
        "DISABLE_USER": ResponseActionType.DISABLE_USER,
        "FORCE_LOGOUT": ResponseActionType.FORCE_LOGOUT,
        "INVESTIGATE": ResponseActionType.INVESTIGATE,
        "IGNORE": ResponseActionType.IGNORE,
        "ALLOWLIST": ResponseActionType.ALLOWLIST_EVENT,
        "ADD_ALLOWLIST": ResponseActionType.ADD_ALLOWLIST
    }

    target_enum = action_type_map.get(action_type_str)
    if not target_enum:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported response action '{action_type_str}'. Allowed: DISABLE_USER, FORCE_LOGOUT, INVESTIGATE, IGNORE, ALLOWLIST"
        )

    parameters = {
        "target_user": username,
        "event_id": event_id,
        "actor": current_user.username,
        "role": current_user.role.value
    }

    action_obj = response_service.execute_response(
        db=db,
        device_id=dev_uuid,
        action_type=target_enum,
        initiated_by=current_user.username,
        user_role=current_user.role.value,
        parameters=parameters
    )

    return {
        "status": "SUCCESS",
        "action_id": str(action_obj.id),
        "action_type": action_obj.action_type.value,
        "device_id": str(dev_uuid),
        "execution_status": action_obj.status.value,
        "result": action_obj.result,
        "audited": True
    }

