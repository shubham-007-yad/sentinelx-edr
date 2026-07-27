from typing import Optional, Set
from app.detection.rules.base import BaseRule, RuleResult
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.scoring import threat_scorer


class DoubleExtensionRule(BaseRule):
    rule_name = "Double Extension Detection"
    threat_type = ThreatType.DOUBLE_EXTENSION
    severity = ThreatSeverity.CRITICAL

    DOC_IMAGE_EXTENSIONS: Set[str] = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".csv", ".zip", ".rar", ".7z"
    }

    EXECUTABLE_EXTENSIONS: Set[str] = {
        ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
        ".ps1", ".js", ".wsf", ".hta", ".cpl", ".com", ".pif"
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
        parts = file_name.lower().split(".")
        if len(parts) >= 3:
            penultimate_ext = f".{parts[-2]}"
            final_ext = f".{parts[-1]}"
            if penultimate_ext in self.DOC_IMAGE_EXTENSIONS and final_ext in self.EXECUTABLE_EXTENSIONS:
                resolved_severity = threat_scorer.get_rule_severity(self.rule_name, default=self.severity)
                return RuleResult(
                    rule_name=self.rule_name,
                    threat_type=self.threat_type,
                    severity=resolved_severity,
                    description=f"Deceptive double extension spoofing ({penultimate_ext}{final_ext}) detected in '{file_name}'. Disguises executable payload as a document or media file."
                )
        return None
