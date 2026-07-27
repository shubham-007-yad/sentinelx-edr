from typing import Optional
from app.detection.rules.base import BaseRule, RuleResult
from app.models.threat import ThreatSeverity, ThreatType


class AutoRunRule(BaseRule):
    rule_name = "USB AutoRun Configuration Script"
    threat_type = ThreatType.AUTORUN_SCRIPT
    severity = ThreatSeverity.HIGH

    def evaluate(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False
    ) -> Optional[RuleResult]:
        name_lower = file_name.lower()
        path_lower = full_path.lower()

        if name_lower == "autorun.inf" or "autorun.inf" in path_lower or name_lower.startswith("autorun."):
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"USB AutoRun configuration file '{file_name}' detected on removable media. Commonly leveraged by USB worm payloads for automatic execution."
            )
        return None
