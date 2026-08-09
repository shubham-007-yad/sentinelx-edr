import os
from typing import Optional, List, Dict, Any
from app.detection.rules.base import BaseRule, RuleResult
from app.models.threat import ThreatType, ThreatSeverity


class FIMExecutableInDownloadsRule(BaseRule):
    rule_name = "FIM Executable Dropped in Downloads"
    rule_id = "RULE-FIM-001"
    rule_version = "1.0.0"
    mitre_attack = "T1204.002"
    confidence = 90.0
    threat_type = ThreatType.FIM_EXECUTABLE_IN_DOWNLOADS
    severity = ThreatSeverity.HIGH

    EXECUTABLE_EXTENSIONS = {
        ".exe", ".elf", ".bin", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".com", ".pif", ".sh", ".cpl", ".hta"
    }

    def evaluate(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False,
        is_executable: bool = False,
        event_type: str = "MODIFIED"
    ) -> Optional[RuleResult]:
        path_lower = full_path.lower()
        ext_clean = (extension.lower() if extension else os.path.splitext(file_name)[1].lower()).strip()
        if ext_clean and not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"

        is_in_downloads = ("downloads" in path_lower or "/downloads" in path_lower or "\\downloads" in path_lower)
        is_exec = (ext_clean in self.EXECUTABLE_EXTENSIONS) or is_executable

        if is_in_downloads and is_exec and event_type in ["CREATED", "MODIFIED", "RENAMED"]:
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Executable binary or installer '{file_name}' dropped or modified in Downloads directory.",
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


class FIMDoubleExtensionRule(BaseRule):
    rule_name = "FIM Double Extension Masquerade"
    rule_id = "RULE-FIM-002"
    rule_version = "1.0.0"
    mitre_attack = "T1036.007"
    confidence = 95.0
    threat_type = ThreatType.FIM_DOUBLE_EXTENSION_MASQUERADE
    severity = ThreatSeverity.CRITICAL

    DOC_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt",
        ".rtf", ".jpg", ".png", ".zip", ".rar", ".7z"
    }
    EXECUTABLE_EXTENSIONS = {
        ".exe", ".elf", ".bin", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".com", ".pif", ".sh"
    }

    def evaluate(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False,
        is_executable: bool = False,
        event_type: str = "MODIFIED"
    ) -> Optional[RuleResult]:
        parts = file_name.lower().split(".")
        if len(parts) >= 3:
            penultimate_ext = f".{parts[-2]}"
            final_ext = f".{parts[-1]}"
            if penultimate_ext in self.DOC_EXTENSIONS and (final_ext in self.EXECUTABLE_EXTENSIONS or is_executable):
                return RuleResult(
                    rule_name=self.rule_name,
                    threat_type=self.threat_type,
                    severity=self.severity,
                    description=f"Office document or image binary '{file_name}' uses double extension masquerade ({penultimate_ext}{final_ext}).",
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    mitre_attack=self.mitre_attack,
                    confidence=self.confidence
                )
        return None


class FIMStartupModificationRule(BaseRule):
    rule_name = "FIM Startup Autostart Folder Modification"
    rule_id = "RULE-FIM-003"
    rule_version = "1.0.0"
    mitre_attack = "T1547.001"
    confidence = 90.0
    threat_type = ThreatType.FIM_STARTUP_MODIFICATION
    severity = ThreatSeverity.HIGH

    STARTUP_KEYWORDS = [
        "startup", "autostart", "/etc/init.d", "/etc/systemd/system",
        "/etc/cron", "runonce"
    ]

    def evaluate(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False,
        is_executable: bool = False,
        event_type: str = "MODIFIED"
    ) -> Optional[RuleResult]:
        path_lower = full_path.lower()
        if any(k in path_lower for k in self.STARTUP_KEYWORDS) and event_type in ["CREATED", "MODIFIED", "RENAMED"]:
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"File event ({event_type}) in persistence startup directory: {full_path}",
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


class FIMMassFileModificationRule(BaseRule):
    rule_name = "FIM Mass File Modification (Ransomware Behavior)"
    rule_id = "RULE-FIM-004"
    rule_version = "1.0.0"
    mitre_attack = "T1486"
    confidence = 98.0
    threat_type = ThreatType.FIM_MASS_FILE_MODIFICATION
    severity = ThreatSeverity.CRITICAL

    def evaluate(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False,
        is_executable: bool = False,
        event_type: str = "MODIFIED",
        modification_count: int = 1,
        window_seconds: float = 10.0
    ) -> Optional[RuleResult]:
        if modification_count >= 10:
            return RuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Mass filesystem modifications detected ({modification_count} files modified within {window_seconds}s). Potential Ransomware activity.",
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None
