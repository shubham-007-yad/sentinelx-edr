from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import uuid


@dataclass
class SubsystemAlertEvent:
    """Represents a telemetry event from USB, Process, Network, FIM, or Ransomware subsystems."""
    subsystem: str         # USB, PROCESS, NETWORK, FIM, RANSOMWARE, EVENT_LOG
    rule_name: str
    description: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    timestamp: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    remote_ip: Optional[str] = None
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subsystem": self.subsystem,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "process_name": self.process_name,
            "file_path": self.file_path,
            "remote_ip": self.remote_ip,
            "raw_payload": self.raw_payload
        }


@dataclass
class UnifiedIncident:
    """
    Unified Multi-Vector Incident.
    Aggregates separate alerts across USB, Process, Network, FIM, and Ransomware subsystems
    into a single root-cause incident tied by a unified correlation_id.
    """
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str = "default_device"
    root_cause_vector: str = "UNKNOWN"  # e.g., "USB Removable Drive Insertion"
    title: str = "Unified Security Incident"
    severity: str = "HIGH"
    status: str = "ACTIVE"              # ACTIVE, CONTAINED, RESOLVED
    composite_score: float = 0.0
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    events: List[SubsystemAlertEvent] = field(default_factory=list)
    attack_chain_summary: List[Dict[str, Any]] = field(default_factory=list)

    def add_subsystem_event(self, event: SubsystemAlertEvent) -> Dict[str, Any]:
        """Appends an event to the unified incident attack chain."""
        self.events.append(event)
        self.last_updated = datetime.now(timezone.utc).isoformat()
        
        # Determine root cause vector if USB or initial process
        if self.root_cause_vector == "UNKNOWN":
            if event.subsystem == "USB":
                self.root_cause_vector = f"USB Drive Insertion ({event.raw_payload.get('drive_letter', 'Removable Drive')})"
            elif event.subsystem == "PROCESS":
                self.root_cause_vector = f"Execution of {event.process_name or 'untrusted binary'}"

        # Re-evaluate incident severity & composite score
        self._reevaluate_incident_severity()
        self._build_attack_chain_summary()

        return self.to_dict()

    def _reevaluate_incident_severity(self):
        subsystems = {e.subsystem for e in self.events}
        severities = {e.severity for e in self.events}
        
        # High correlation score if multi-vector attack sequence is present
        score = len(self.events) * 15.0
        
        if "RANSOMWARE" in subsystems or "CRITICAL" in severities or len(subsystems) >= 3:
            self.severity = "CRITICAL"
            score = max(score, 95.0)
            self.title = f"🚨 Critical Unified Ransomware Incident ({self.root_cause_vector})"
        elif "NETWORK" in subsystems and "PROCESS" in subsystems:
            self.severity = "HIGH"
            score = max(score, 75.0)
            self.title = f"⚠️ Multi-Vector C2 Execution Incident ({self.root_cause_vector})"
        
        self.composite_score = min(100.0, round(score, 2))

    def _build_attack_chain_summary(self):
        """Constructs the step-by-step attack storyline chain."""
        self.attack_chain_summary = []
        for idx, ev in enumerate(self.events, 1):
            self.attack_chain_summary.append({
                "step": idx,
                "timestamp": ev.timestamp,
                "subsystem": ev.subsystem,
                "action": ev.rule_name,
                "description": ev.description,
                "severity": ev.severity
            })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "correlation_id": self.correlation_id,
            "device_id": self.device_id,
            "root_cause_vector": self.root_cause_vector,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "composite_score": self.composite_score,
            "start_time": self.start_time,
            "last_updated": self.last_updated,
            "total_correlated_alerts": len(self.events),
            "subsystems_involved": list({e.subsystem for e in self.events}),
            "attack_chain_summary": self.attack_chain_summary,
            "raw_events": [e.to_dict() for e in self.events]
        }


class IncidentCorrelationEngine:
    """
    Phase 7 — Incident Correlation Engine.
    Stitches separate alerts across USB, Process, Network, FIM, and Ransomware subsystems
    into a single unified root-cause incident tied to a single correlation_id.
    """

    def __init__(self, correlation_window_seconds: float = 300.0):
        self.correlation_window_seconds = correlation_window_seconds
        # Mapping from device_id -> active UnifiedIncident
        self.active_incidents: Dict[str, UnifiedIncident] = {}
        # Mapping from correlation_id -> UnifiedIncident
        self.incident_registry: Dict[str, UnifiedIncident] = {}

    def correlate_event(
        self,
        device_id: str,
        subsystem: str,
        rule_name: str,
        description: str,
        severity: str = "HIGH",
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        file_path: Optional[str] = None,
        remote_ip: Optional[str] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        existing_correlation_id: Optional[str] = None
    ) -> UnifiedIncident:
        """
        Ingests a subsystem alert and attaches it to an existing correlation_id chain
        or starts a new unified incident.
        """
        now_ts = datetime.now(timezone.utc).isoformat()
        alert_event = SubsystemAlertEvent(
            subsystem=subsystem.upper(),
            rule_name=rule_name,
            description=description,
            severity=severity.upper(),
            timestamp=now_ts,
            pid=pid,
            process_name=process_name,
            file_path=file_path,
            remote_ip=remote_ip,
            raw_payload=raw_payload or {}
        )

        incident: Optional[UnifiedIncident] = None

        # 1. Look up by explicit correlation_id if provided
        if existing_correlation_id and existing_correlation_id in self.incident_registry:
            incident = self.incident_registry[existing_correlation_id]
        
        # 2. Look up active incident for device_id within sliding window
        if not incident and device_id in self.active_incidents:
            candidate = self.active_incidents[device_id]
            # Check window time
            try:
                last_dt = datetime.fromisoformat(candidate.last_updated)
                elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds()
                if elapsed <= self.correlation_window_seconds:
                    incident = candidate
            except Exception:
                incident = candidate

        # 3. If no active incident exists, initialize a new UnifiedIncident
        if not incident:
            corr_id = existing_correlation_id or str(uuid.uuid4())
            incident = UnifiedIncident(
                correlation_id=corr_id,
                device_id=device_id
            )
            self.active_incidents[device_id] = incident
            self.incident_registry[corr_id] = incident

        # Attach event to unified incident
        incident.add_subsystem_event(alert_event)
        return incident

    def get_incident(self, correlation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a unified incident by correlation_id."""
        inc = self.incident_registry.get(correlation_id)
        if inc:
            return inc.to_dict()
        return None

    def list_unified_incidents(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all unified correlated incidents."""
        results = []
        for inc in self.incident_registry.values():
            if device_id and inc.device_id != device_id:
                continue
            results.append(inc.to_dict())
        return results


incident_correlator = IncidentCorrelationEngine()

