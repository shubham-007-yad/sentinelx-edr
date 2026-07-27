from typing import Optional
from app.detection.rules.base import BaseRule, RuleResult
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.scoring import threat_scorer


class AutoRunRule(BaseRule):
    rule_name = "Autorun Detection"
    threat_type = ThreatType.AUTORUN_SCRIPT
    severity = ThreatSeverity.CRITICAL

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
            resolved_severity = threat_scorer.get_rule_severity(self.rule_name, default=self.severity)
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=resolved_severity,
                description=f"USB AutoRun configuration file '{file_name}' detected on removable media. Classic USB-based persistence mechanism used for automatic malware execution."
            )
        return None
