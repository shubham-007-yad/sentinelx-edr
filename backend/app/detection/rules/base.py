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
