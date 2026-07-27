from typing import List, Optional
from app.detection.rules.base import BaseRule, RuleResult
from app.detection.rules.dangerous_extensions import DangerousExtensionRule, HiddenExecutableRule
from app.detection.rules.autorun import AutoRunRule
from app.detection.rules.double_extension import DoubleExtensionRule
from app.detection.rules.known_malware import KnownMalwareRule
from app.detection.rules.anomalous_file import AnomalousFileRule


class DetectionEngine:
    """
    Modular Detection Rule Engine for SentinelX EDR.
    Evaluates file metadata records against registered rule plugins.
    """

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        if rules is None:
            self.rules: List[BaseRule] = [
                KnownMalwareRule(),
                DoubleExtensionRule(),
                HiddenExecutableRule(),
                AutoRunRule(),
                DangerousExtensionRule(),
                AnomalousFileRule(),
            ]
        else:
            self.rules = list(rules)

    def register_rule(self, rule: BaseRule) -> None:
        """Dynamically registers a new detection rule at runtime."""
        self.rules.append(rule)

    def evaluate_file(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False
    ) -> List[RuleResult]:
        """
        Evaluates a file against all registered rules in the detection engine.
        Returns a list of RuleResult objects for all matching rules.
        """
        findings: List[RuleResult] = []
        for rule in self.rules:
            result = rule.evaluate(
                file_name=file_name,
                full_path=full_path,
                extension=extension,
                file_size=file_size,
                sha256=sha256,
                is_hidden=is_hidden
            )
            if result is not None:
                findings.append(result)
        return findings
