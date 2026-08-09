from typing import Optional, List, Dict, Any
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.network.base import BaseNetworkRule, NetworkRuleResult


class ExcessiveConnectionsRule(BaseNetworkRule):
    """
    Detects excessive outbound connections from a single process (e.g. powershell.exe establishing 300 connections).
    Generates: 'Excessive Network Activity'.
    Default threshold: >= 20 concurrent outbound connections per process.
    """

    rule_name: str = "Excessive Network Activity"
    rule_id: str = "NET-RULE-0003"
    rule_version: str = "1.0.0"
    mitre_attack: str = "T1041"
    confidence: float = 90.0
    threat_type: ThreatType = ThreatType.EXCESSIVE_CONNECTIONS
    severity: ThreatSeverity = ThreatSeverity.HIGH

    def __init__(self, connection_threshold: int = 20):
        self.connection_threshold = connection_threshold

    def evaluate_connection(
        self,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_port: Optional[int] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        protocol: str = "TCP",
        state: Optional[str] = None
    ) -> Optional[NetworkRuleResult]:
        # Single connection pass-through evaluation not triggered for batch-level rule
        return None

    def evaluate_process_connections(
        self,
        pid: int,
        process_name: str,
        connection_count: int,
        sample_connection: Optional[Dict[str, Any]] = None
    ) -> Optional[NetworkRuleResult]:
        """
        Evaluates active connection count for a specific process/PID.
        """
        if connection_count >= self.connection_threshold:
            local_ip = sample_connection.get("local_ip") if sample_connection else None
            local_port = sample_connection.get("local_port") if sample_connection else None
            remote_ip = sample_connection.get("remote_ip") if sample_connection else None
            remote_port = sample_connection.get("remote_port") if sample_connection else None
            protocol = sample_connection.get("protocol", "TCP") if sample_connection else "TCP"

            desc = (
                f"Excessive Network Activity: Process '{process_name}' (PID {pid}) "
                f"opened {connection_count} active outbound connections (Threshold: {self.connection_threshold})."
            )
            return NetworkRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=desc,
                pid=pid,
                process_name=process_name,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )

        return None
