from typing import Optional, Set
from app.detection.rules.base import BaseRule, RuleResult
from app.models.threat import ThreatSeverity, ThreatType


class AnomalousFileRule(BaseRule):
    rule_name = "Anomalous System Process Masquerading"
    threat_type = ThreatType.ANOMALOUS_FILE
    severity = ThreatSeverity.HIGH

    ANOMALOUS_SYSTEM_NAMES: Set[str] = {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
        "smss.exe", "winlogon.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "explorer.exe"
    }

    def evaluate(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False
    ) -> Optional[RuleResult]:
        if file_name.lower() in self.ANOMALOUS_SYSTEM_NAMES:
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"File '{file_name}' matches critical OS system process name but is staged on removable media, indicating potential masquerading."
            )
        return None
