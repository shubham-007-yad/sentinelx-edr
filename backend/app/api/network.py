from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.network import (
    NetworkConnectionBatchIngestRequest, NetworkConnectionOut,
    NetworkEventDiffPayload, NetworkEventSummaryResponse,
    NetworkCorrelatedPivotResponse, ConnectionTimelineResponse
)
from app.schemas.security_policy import NetworkPolicyConfigSchema, SecurityPolicyCreate
from app.services import network_service, device_service
from app.services.policy_service import PolicyService
from app.models.security_policy import PolicyCategory

router = APIRouter(prefix="/network", tags=["Network Connections"])


# ==================== NETWORK SECURITY POLICY ====================

@router.get(
    "/policy",
    response_model=NetworkPolicyConfigSchema,
    status_code=status.HTTP_200_OK,
    summary="Get active Network Security Policy",
    description="Retrieves the active network security policy configuration enforced across endpoints."
)
def get_network_security_policy(db: Session = Depends(get_db)):
    """
    Get active network security policy settings.
    """
    return PolicyService.get_active_network_policy(db=db)


@router.put(
    "/policy",
    response_model=NetworkPolicyConfigSchema,
    status_code=status.HTTP_200_OK,
    summary="Update Network Security Policy",
    description="Updates or creates central Network security policy configuration."
)
def update_network_security_policy(
    policy_in: NetworkPolicyConfigSchema,
    db: Session = Depends(get_db)
):
    """
    Update active network security policy settings.
    """
    active_policies = PolicyService.get_policies(db=db, category=PolicyCategory.NETWORK, enabled_only=True)
    if active_policies:
        active_policy = active_policies[0]
        updated = PolicyService.update_policy(
            db=db,
            policy_id=str(active_policy.id),
            payload=SecurityPolicyCreate(
                policy_name=active_policy.policy_name,
                category=PolicyCategory.NETWORK,
                version=active_policy.version,
                enabled=True,
                priority=active_policy.priority,
                configuration=policy_in.model_dump(),
                created_by="Admin"
            )
        )
        return updated.configuration
    else:
        created = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Central Network Security Policy",
                category=PolicyCategory.NETWORK,
                version=1,
                enabled=True,
                priority=100,
                configuration=policy_in.model_dump(),
                created_by="Admin"
            )
        )
        return created.configuration



@router.get(
    "/connections",
    response_model=List[NetworkConnectionOut],
    status_code=status.HTTP_200_OK,
    summary="List all active network connections",
    description="Retrieves endpoint network connection telemetry across managed devices with optional filtering."
)
def list_network_connections(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    device_id: Optional[UUID] = Query(None, description="Filter connections by Device UUID"),
    pid: Optional[int] = Query(None, description="Filter by PID"),
    process_name: Optional[str] = Query(None, description="Filter by process binary name"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (TCP/UDP)"),
    state: Optional[str] = Query(None, description="Filter by socket state (ESTABLISHED, LISTEN, etc.)"),
    remote_ip: Optional[str] = Query(None, description="Filter by remote IP address"),
    db: Session = Depends(get_db)
):
    return network_service.get_network_connections(
        db=db,
        skip=skip,
        limit=limit,
        device_id=device_id,
        pid=pid,
        process_name=process_name,
        protocol=protocol,
        state=state,
        remote_ip=remote_ip
    )


@router.get(
    "/connections/{id}/correlated",
    response_model=NetworkCorrelatedPivotResponse,
    status_code=status.HTTP_200_OK,
    summary="Get 360° correlated network investigation pivot",
    description="Retrieves fully correlated telemetry linking Network Connection ➔ Process ➔ Device ➔ Threat ➔ Alert ➔ Response Actions."
)
def get_correlated_network_connection_endpoint(
    id: UUID,
    db: Session = Depends(get_db)
):
    correlated = network_service.get_correlated_network_connection(db=db, connection_id=id)
    if not correlated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network connection with ID '{id}' was not found."
        )
    return correlated


@router.get(
    "/connections/{id}/timeline",
    response_model=ConnectionTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get connection investigation timeline",
    description="Retrieves step-by-step chronological event timeline (Process start ➔ Connected ➔ Data transfer ➔ Beacon ➔ Alert ➔ Blocked)."
)
def get_connection_timeline_endpoint(
    id: UUID,
    db: Session = Depends(get_db)
):
    timeline_res = network_service.get_connection_timeline(db=db, connection_id=id)
    if not timeline_res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network connection with ID '{id}' was not found."
        )
    return timeline_res


@router.post(
    "/{device_id}",
    response_model=List[NetworkConnectionOut],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest network connection inventory",
    description="Ingests network connection telemetry snapshot from an endpoint agent for a target device."
)
def ingest_device_network_connections(
    device_id: UUID,
    payload: NetworkConnectionBatchIngestRequest,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    return network_service.ingest_network_connections(
        db=db,
        device_id=device_id,
        connections_in=payload.connections
    )


@router.post(
    "/events/{device_id}",
    response_model=NetworkEventSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest live network diff events",
    description="Processes real-time connection diff events (connected, disconnected, state_changed, long_running)."
)
def ingest_live_network_events(
    device_id: UUID,
    payload: NetworkEventDiffPayload,
    db: Session = Depends(get_db)
):
    device = device_service.get_device_by_id(db=db, device_id=device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with ID '{device_id}' was not found."
        )

    return network_service.process_live_network_events(
        db=db,
        device_id=device_id,
        events=payload
    )
