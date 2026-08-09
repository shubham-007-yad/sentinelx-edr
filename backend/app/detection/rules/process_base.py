from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass
from app.models.threat import ThreatSeverity, ThreatType


@dataclass
class ProcessRuleResult:
    rule_name: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    pid: int
    process_name: str
    cmdline: Optional[str] = None
    exe_path: Optional[str] = None
    username: Optional[str] = None
    ppid: Optional[int] = None
    parent_name: Optional[str] = None
    chain_summary: Optional[str] = None
    score: int = 0
    rule_id: Optional[str] = "RULE-0000"
    rule_version: Optional[str] = "1.0.0"
    mitre_attack: Optional[str] = "T1059"
    confidence: float = 95.0

    def __post_init__(self):
        if self.score == 0 and self.severity:
            from app.detection.scoring import threat_scorer
            self.score = threat_scorer.get_severity_score(self.severity)


class BaseProcessRule(ABC):
    """Abstract base class for all process behavioral detection rules in SentinelX EDR."""

    rule_name: str
    rule_id: str = "RULE-0000"
    rule_version: str = "1.0.0"
    mitre_attack: str = "T1059"
    confidence: float = 95.0
    threat_type: ThreatType
    severity: ThreatSeverity

    @abstractmethod
    def evaluate_process(
        self,
        pid: int,
        name: str,
        cmdline: Optional[str] = None,
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
        ppid: Optional[int] = None
    ) -> Optional[ProcessRuleResult]:
        """
        Evaluates running process metadata and command-line arguments against behavioral rule heuristics.
        Returns a ProcessRuleResult if a behavioral threat is detected, otherwise None.
        """
        pass
