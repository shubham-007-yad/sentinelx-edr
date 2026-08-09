from typing import Optional
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.rules.process_base import BaseProcessRule, ProcessRuleResult


class SuspiciousPowerShellRule(BaseProcessRule):
    """
    Detects suspicious PowerShell execution patterns:
    - Encoded command lines (-enc, -encodedcommand)
    - Memory injection strings (DownloadString, IEX, Net.WebClient)
    - Execution policy / window style evasion (-w hidden, -nop, -noni)
    """

    rule_name = "SuspiciousPowerShellRule"
    rule_id = "RULE-0001"
    rule_version = "1.0.0"
    mitre_attack = "T1059.001"
    confidence = 98.0
    threat_type = ThreatType.SUSPICIOUS_POWERSHELL
    severity = ThreatSeverity.HIGH

    POWERSHELL_NAMES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}

    DOWNLOAD_PATTERNS = [
        "downloadstring", "downloadfile", "net.webclient",
        "invoke-webrequest", "iwr", "bitstransfer", "start-bitstransfer",
        "iex", "invoke-expression"
    ]

    ENCODED_PATTERNS = [
        "-enc", "-encodedcommand", "-e ", "-e:", "-encoded"
    ]

    HIDDEN_EVASION_PATTERNS = [
        "-w hidden", "-windowstyle hidden", "-nop", "-noprofile",
        "-noni", "-noninteractive"
    ]

    def evaluate_process(
        self,
        pid: int,
        name: str,
        cmdline: Optional[str] = None,
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
        ppid: Optional[int] = None
    ) -> Optional[ProcessRuleResult]:
        if not name or name.lower() not in self.POWERSHELL_NAMES:
            return None

        cmdline_lower = (cmdline or "").lower()

        # 1. Check for Download & Execute behavior (CRITICAL)
        for pattern in self.DOWNLOAD_PATTERNS:
            if pattern in cmdline_lower:
                return ProcessRuleResult(
                    rule_name=self.rule_name,
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    mitre_attack=self.mitre_attack,
                    confidence=self.confidence,
                    threat_type=self.threat_type,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"PowerShell download-and-execute memory injection pattern detected ('{pattern}')",
                    pid=pid,
                    process_name=name,
                    cmdline=cmdline,
                    exe_path=exe_path,
                    username=username
                )

        # 2. Check for Encoded Command Lines (HIGH)
        for pattern in self.ENCODED_PATTERNS:
            if pattern in cmdline_lower:
                return ProcessRuleResult(
                    rule_name=self.rule_name,
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    mitre_attack=self.mitre_attack,
                    confidence=self.confidence,
                    threat_type=self.threat_type,
                    severity=ThreatSeverity.HIGH,
                    description=f"Encoded PowerShell command execution detected ('{pattern}')",
                    pid=pid,
                    process_name=name,
                    cmdline=cmdline,
                    exe_path=exe_path,
                    username=username
                )

        # 3. Check for Hidden Execution / Evasion Flags (HIGH)
        for pattern in self.HIDDEN_EVASION_PATTERNS:
            if pattern in cmdline_lower:
                return ProcessRuleResult(
                    rule_name=self.rule_name,
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    mitre_attack=self.mitre_attack,
                    confidence=self.confidence,
                    threat_type=self.threat_type,
                    severity=ThreatSeverity.HIGH,
                    description=f"PowerShell execution with hidden window / evasion flags detected ('{pattern}')",
                    pid=pid,
                    process_name=name,
                    cmdline=cmdline,
                    exe_path=exe_path,
                    username=username
                )

        return None
