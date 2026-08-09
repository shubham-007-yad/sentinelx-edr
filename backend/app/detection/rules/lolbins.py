from typing import Optional
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.rules.process_base import BaseProcessRule, ProcessRuleResult


class LOLBinsRule(BaseProcessRule):
    """
    Detects abuse of Living-off-the-Land Binaries (LOLBins) across Windows and Linux:
    - certutil, regsvr32, rundll32, mshta, wmic, bitsadmin, cscript, wscript
    - curl/wget piped to shell, nc/netcat/socat reverse shell execution
    """

    rule_name = "LOLBinsRule"
    rule_id = "RULE-0003"
    rule_version = "1.0.0"
    mitre_attack = "T1105"
    confidence = 96.0
    threat_type = ThreatType.LOLBIN_ABUSE
    severity = ThreatSeverity.HIGH

    LOLBIN_RULES = [
        {
            "names": {"certutil.exe", "certutil"},
            "patterns": ["-urlcache", "-split", "-f", "http://", "https://"],
            "severity": ThreatSeverity.CRITICAL,
            "desc": "CertUtil Living-off-the-Land remote binary download attempt"
        },
        {
            "names": {"regsvr32.exe", "regsvr32"},
            "patterns": ["/s", "/u", "/i:", "scrobj.dll", "http"],
            "severity": ThreatSeverity.CRITICAL,
            "desc": "Regsvr32 Squiblydoo Living-off-the-Land remote script execution"
        },
        {
            "names": {"rundll32.exe", "rundll32"},
            "patterns": ["javascript:", "url.dll", "http://", "https://"],
            "severity": ThreatSeverity.CRITICAL,
            "desc": "Rundll32 Living-off-the-Land malicious payload execution"
        },
        {
            "names": {"mshta.exe", "mshta"},
            "patterns": ["http://", "https://", ".hta", "javascript:", "vbscript:"],
            "severity": ThreatSeverity.CRITICAL,
            "desc": "MSHTA Living-off-the-Land HTA remote code execution"
        },
        {
            "names": {"wmic.exe", "wmic"},
            "patterns": ["process call create", "shadowcopy delete", "shadowcopy get"],
            "severity": ThreatSeverity.HIGH,
            "desc": "WMIC Living-off-the-Land malicious command execution"
        },
        {
            "names": {"bitsadmin.exe", "bitsadmin"},
            "patterns": ["/transfer", "http://", "https://"],
            "severity": ThreatSeverity.HIGH,
            "desc": "BITSAdmin Living-off-the-Land file transfer download"
        },
        {
            "names": {"cscript.exe", "wscript.exe", "cscript", "wscript"},
            "patterns": ["/tmp", "appdata\\local\\temp", "temp\\"],
            "severity": ThreatSeverity.HIGH,
            "desc": "CScript/WScript script execution from temporary directory"
        },
        {
            "names": {"curl", "wget"},
            "patterns": ["| bash", "| sh", "-o /tmp", "http://", "https://"],
            "severity": ThreatSeverity.HIGH,
            "desc": "Linux curl/wget Living-off-the-Land payload download & execution"
        },
        {
            "names": {"nc", "netcat", "ncat", "socat"},
            "patterns": ["-e /bin/bash", "-e /bin/sh", "-e cmd.exe", "-e powershell"],
            "severity": ThreatSeverity.CRITICAL,
            "desc": "Netcat/Socat Living-off-the-Land reverse shell spawn"
        }
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
        if not name:
            return None

        proc_name_lower = name.lower()
        cmdline_lower = (cmdline or "").lower()
        exe_path_lower = (exe_path or "").lower()

        for lolbin in self.LOLBIN_RULES:
            if proc_name_lower in lolbin["names"]:
                # Check for suspicious command line pattern match
                for pattern in lolbin["patterns"]:
                    if pattern in cmdline_lower or pattern in exe_path_lower:
                        return ProcessRuleResult(
                            rule_name=self.rule_name,
                            rule_id=self.rule_id,
                            rule_version=self.rule_version,
                            mitre_attack=self.mitre_attack,
                            confidence=self.confidence,
                            threat_type=self.threat_type,
                            severity=lolbin["severity"],
                            description=f"{lolbin['desc']} (pattern matched: '{pattern}')",
                            pid=pid,
                            process_name=name,
                            cmdline=cmdline,
                            exe_path=exe_path,
                            username=username
                        )

        return None
