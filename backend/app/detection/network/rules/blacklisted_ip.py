from typing import Optional
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.network.base import BaseNetworkRule, NetworkRuleResult
from app.detection.network.reputation import IPReputationProvider, LocalIPReputationProvider


class BlacklistedIPRule(BaseNetworkRule):
    """
    Detects network connections attempting to communicate with known blacklisted / C2 IP addresses.
    Uses configurable IPReputationProvider interface (Local MVP, pluggable for AbuseIPDB, OTX, VT, MISP).
    """

    rule_name: str = "Blacklisted IP Communication"
    rule_id: str = "NET-RULE-0002"
    rule_version: str = "1.0.0"
    mitre_attack: str = "T1071"
    confidence: float = 95.0
    threat_type: ThreatType = ThreatType.BLACK_LISTED_IP
    severity: ThreatSeverity = ThreatSeverity.HIGH

    def __init__(self, reputation_provider: Optional[IPReputationProvider] = None):
        self.reputation_provider = reputation_provider or LocalIPReputationProvider()

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
        if not remote_ip:
            return None

        rep_hit = self.reputation_provider.check_ip(remote_ip)
        if rep_hit:
            proc_str = f"Process '{process_name}' (PID {pid})" if process_name else f"PID {pid}" if pid else "Endpoint process"
            provider_name = rep_hit.get("provider", "ReputationProvider")
            desc = (
                f"{proc_str} connected to blacklisted IP {remote_ip}:{remote_port} "
                f"[{protocol} | Flagged by {provider_name} | Category: {rep_hit.get('category', 'Malicious IP')}]."
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
                confidence=rep_hit.get("confidence", self.confidence)
            )

        return None
