from typing import Optional, Set
from app.detection.rules.base import BaseRule, RuleResult
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.scoring import threat_scorer


class DangerousExtensionRule(BaseRule):
    rule_name = "Dangerous Extension Detection"
    threat_type = ThreatType.SUSPICIOUS_EXTENSION
    severity = ThreatSeverity.HIGH

    DANGEROUS_EXTENSIONS: Set[str] = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".js",
        ".sys", ".vbe", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".reg", ".lnk", ".pif"
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
        ext_clean = (extension.lower() if extension else "").strip()
        if not ext_clean and "." in file_name:
            ext_clean = f".{file_name.rsplit('.', 1)[-1].lower()}"
        elif ext_clean and not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"

        if ext_clean in self.DANGEROUS_EXTENSIONS:
            resolved_severity = threat_scorer.get_extension_severity(ext_clean, default=self.severity)
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=resolved_severity,
                description=f"Dangerous executable or script format '{ext_clean}' detected on removable USB drive ({file_name})."
            )
        return None


class HiddenExecutableRule(BaseRule):
    rule_name = "Hidden Executable File on Removable Media"
    threat_type = ThreatType.HIDDEN_EXECUTABLE
    severity = ThreatSeverity.HIGH

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
        name_lower = file_name.lower()
        ext_clean = (extension.lower() if extension else "").strip()
        if ext_clean and not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"

        is_dotfile = name_lower.startswith(".") and len(name_lower) > 1
        if (is_hidden or is_dotfile) and (ext_clean in self.EXECUTABLE_EXTENSIONS):
            resolved_severity = threat_scorer.get_rule_severity(self.rule_name, default=self.severity)
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=resolved_severity,
                description=f"Executable binary or script '{file_name}' has hidden file attribute set on removable USB storage."
            )
        return None
