from typing import Optional, Set
from app.detection.rules.base import BaseRule, RuleResult
from app.models.threat import ThreatSeverity, ThreatType


class DangerousExtensionRule(BaseRule):
    rule_name = "Dangerous Script Extension on USB"
    threat_type = ThreatType.SUSPICIOUS_EXTENSION
    severity = ThreatSeverity.HIGH

    SCRIPT_EXTENSIONS: Set[str] = {
        ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".scr", ".hta",
        ".js", ".jse", ".wsf", ".wsh", ".cpl", ".reg", ".lnk", ".pif"
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
        if ext_clean and not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"

        if ext_clean in self.SCRIPT_EXTENSIONS:
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Potentially dangerous script/executable format ({ext_clean}) detected on removable USB storage media."
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
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Executable binary or script '{file_name}' has hidden file attribute set on removable USB storage."
            )
        return None
