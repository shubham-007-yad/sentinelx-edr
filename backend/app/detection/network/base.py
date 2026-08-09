from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass
from app.models.threat import ThreatSeverity, ThreatType


@dataclass
class NetworkRuleResult:
    rule_name: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: str = "TCP"
    state: Optional[str] = None
    score: int = 0
    rule_id: Optional[str] = "NET-RULE-0000"
    rule_version: Optional[str] = "1.0.0"
    mitre_attack: Optional[str] = "T1071"
    confidence: float = 90.0

    def __post_init__(self):
        if self.score == 0 and self.severity:
            from app.detection.scoring import threat_scorer
            self.score = threat_scorer.get_severity_score(self.severity)


class BaseNetworkRule(ABC):
    """Abstract base class for all network detection rules in SentinelX EDR."""

    rule_name: str
    rule_id: str = "NET-RULE-0000"
    rule_version: str = "1.0.0"
    mitre_attack: str = "T1071"
    confidence: float = 90.0
    threat_type: ThreatType
    severity: ThreatSeverity

    @abstractmethod
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
        """
        Evaluates network connection telemetry against rule conditions.
        Returns NetworkRuleResult if a network threat condition is met, otherwise None.
        """
        pass
