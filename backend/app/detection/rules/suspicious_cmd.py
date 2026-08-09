from typing import Optional
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.rules.process_base import BaseProcessRule, ProcessRuleResult


class SuspiciousCmdRule(BaseProcessRule):
    """
    Detects suspicious CMD process executions:
    - Silent execution & piping into PowerShell / Shell
    - Command chaining (&, &&, ||) in /c subshells
    - Running from temporary directories (%TEMP%, /tmp, /dev/shm)
    """

    rule_name = "SuspiciousCmdRule"
    rule_id = "RULE-0004"
    rule_version = "1.0.0"
    mitre_attack = "T1059.003"
    confidence = 92.0
    threat_type = ThreatType.SUSPICIOUS_CMD
    severity = ThreatSeverity.HIGH

    CMD_NAMES = {"cmd.exe", "cmd"}

    TEMP_PATHS = ["appdata\\local\\temp", "/tmp", "/dev/shm", "temp\\"]

    def evaluate_process(
        self,
        pid: int,
        name: str,
        cmdline: Optional[str] = None,
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
        ppid: Optional[int] = None
    ) -> Optional[ProcessRuleResult]:
        if not name or name.lower() not in self.CMD_NAMES:
            return None

        cmdline_lower = (cmdline or "").lower()
        exe_path_lower = (exe_path or "").lower()

        # 1. Check for Piping into PowerShell / Shell (HIGH)
        if "powershell" in cmdline_lower or "| bash" in cmdline_lower or "| sh" in cmdline_lower:
            return ProcessRuleResult(
                rule_name=self.rule_name,
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence,
                threat_type=self.threat_type,
                severity=ThreatSeverity.HIGH,
                description="Silent CMD execution with shell/PowerShell piping detected",
                pid=pid,
                process_name=name,
                cmdline=cmdline,
                exe_path=exe_path,
                username=username
            )

        # 2. Check for Execution out of Temp directories (HIGH)
        for temp_path in self.TEMP_PATHS:
            if temp_path in exe_path_lower or temp_path in cmdline_lower:
                return ProcessRuleResult(
                    rule_name=self.rule_name,
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    mitre_attack=self.mitre_attack,
                    confidence=self.confidence,
                    threat_type=self.threat_type,
                    severity=ThreatSeverity.HIGH,
                    description=f"CMD process executing from temporary directory location ('{temp_path}')",
                    pid=pid,
                    process_name=name,
                    cmdline=cmdline,
                    exe_path=exe_path,
                    username=username
                )

        # 3. Check for Script / Command Chaining (MEDIUM)
        if ("/c" in cmdline_lower or "/k" in cmdline_lower) and ("&&" in cmdline_lower or "||" in cmdline_lower or " & " in cmdline_lower):
            return ProcessRuleResult(
                rule_name=self.rule_name,
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence,
                threat_type=self.threat_type,
                severity=ThreatSeverity.MEDIUM,
                description="Suspicious CMD multi-command script chaining detected",
                pid=pid,
                process_name=name,
                cmdline=cmdline,
                exe_path=exe_path,
                username=username
            )

        return None
