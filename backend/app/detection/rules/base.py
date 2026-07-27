from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass
from app.models.threat import ThreatSeverity, ThreatType


@dataclass
class RuleResult:
    rule_name: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    score: int = 0

    def __post_init__(self):
        if self.score == 0 and self.severity:
            from app.detection.scoring import threat_scorer
            self.score = threat_scorer.get_severity_score(self.severity)



class BaseRule(ABC):
    """Abstract base class for all detection rules in SentinelX EDR."""

    rule_name: str
    threat_type: ThreatType
    severity: ThreatSeverity

    @abstractmethod
    def evaluate(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False
    ) -> Optional[RuleResult]:
        """
        Evaluates file metadata against this rule.
        Returns a RuleResult if a threat condition is met, otherwise None.
        """
        pass
