from typing import Optional, Set
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.network.base import BaseNetworkRule, NetworkRuleResult


class SuspiciousPortRule(BaseNetworkRule):
    """
    Detects network connections attempting to bind or connect to known suspicious / C2 / trojan ports.
    Configurable port list defaults: {4444, 1337, 31337, 5555, 6667}.
    """

    rule_name: str = "Suspicious Network Port Connection"
    rule_id: str = "NET-RULE-0001"
    rule_version: str = "1.0.0"
    mitre_attack: str = "T1571"
    confidence: float = 90.0
    threat_type: ThreatType = ThreatType.SUSPICIOUS_NETWORK_PORT
    severity: ThreatSeverity = ThreatSeverity.HIGH

    DEFAULT_SUSPICIOUS_PORTS: Set[int] = {4444, 1337, 31337, 5555, 6667}

    def __init__(self, suspicious_ports: Optional[Set[int]] = None):
        self.suspicious_ports = set(suspicious_ports) if suspicious_ports is not None else set(self.DEFAULT_SUSPICIOUS_PORTS)

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
        matched_port = None
        port_type = None

        if remote_port and remote_port in self.suspicious_ports:
            matched_port = remote_port
            port_type = "remote"
        elif local_port and local_port in self.suspicious_ports:
            matched_port = local_port
            port_type = "local"

        if matched_port:
            proc_str = f"Process '{process_name}' (PID {pid})" if process_name else f"PID {pid}" if pid else "Unknown process"
            desc = (
                f"{proc_str} established connection to suspicious {port_type} port {matched_port} "
                f"[{protocol} | Local: {local_ip}:{local_port} -> Remote: {remote_ip}:{remote_port}]."
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
                state=state,
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )

        return None
