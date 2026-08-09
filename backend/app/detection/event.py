from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from uuid import UUID


@dataclass
class DetectionEvent:
    """
    Common Internal Event Model for SentinelX EDR:
    Standardized telemetry detection event emitted by USB, File, Process, or Network subsystems.
    """
    source_subsystem: str  # "USB", "FILE", "PROCESS", "NETWORK"
    device_id: UUID
    rule_id: str
    rule_name: str
    threat_type: str       # e.g., "KNOWN_MALWARE", "LOLBIN_ABUSE", "C2_BEACONING"
    severity: str          # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str

    # Contextual Telemetry Identifiers
    pid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None

    mitre_attack: Optional[str] = None
    confidence: float = 100.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_subsystem": self.source_subsystem,
            "device_id": str(self.device_id),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description,
            "pid": self.pid,
            "process_name": self.process_name,
            "executable_path": self.executable_path,
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "protocol": self.protocol,
            "mitre_attack": self.mitre_attack,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat()
        }
