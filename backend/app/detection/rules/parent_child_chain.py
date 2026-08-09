from typing import Optional, Dict, Any, List
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.rules.process_base import BaseProcessRule, ProcessRuleResult


class ParentChildChainRule(BaseProcessRule):
    """
    Detects suspicious Parent-Child process execution chains:
    - Office/PDF/Web Applications spawning shells or LOLBins
    - Shell-to-shell evasion chains (explorer.exe -> powershell.exe -> cmd.exe)
    - Multilevel process tree lineage analysis
    """

    rule_name = "ParentChildChainRule"
    rule_id = "RULE-0002"
    rule_version = "1.0.0"
    mitre_attack = "T1059"
    confidence = 95.0
    threat_type = ThreatType.SUSPICIOUS_PROCESS_BEHAVIOR
    severity = ThreatSeverity.HIGH

    OFFICE_BROWSER_PARENTS = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "acrord32.exe", "chrome.exe", "firefox.exe", "msedge.exe",
        "nginx", "apache2", "httpd", "w3wp.exe", "php-fpm"
    }

    SUSPICIOUS_SHELL_CHILDREN = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "powershell", "pwsh",
        "bash", "sh", "cscript.exe", "wscript.exe", "certutil.exe",
        "regsvr32.exe", "mshta.exe"
    }

    SHELL_NAMES = {"cmd.exe", "cmd", "powershell.exe", "pwsh.exe", "powershell", "pwsh", "bash", "sh"}

    def evaluate_process(
        self,
        pid: int,
        name: str,
        cmdline: Optional[str] = None,
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
        ppid: Optional[int] = None
    ) -> Optional[ProcessRuleResult]:
        return self.evaluate_process_chain(
            pid=pid,
            name=name,
            ppid=ppid,
            parent_name=None,
            cmdline=cmdline,
            exe_path=exe_path,
            username=username
        )

    def evaluate_process_chain(
        self,
        pid: int,
        name: str,
        ppid: Optional[int] = None,
        parent_name: Optional[str] = None,
        cmdline: Optional[str] = None,
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
        process_ancestors: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[ProcessRuleResult]:
        """
        Evaluates process relationship with parent process name and process tree ancestry.
        """
        proc_name_lower = (name or "").lower()
        parent_name_lower = (parent_name or "").lower() if parent_name else ""

        # 1. Office / Browser / Web App spawning Shell / LOLBin (CRITICAL)
        if parent_name_lower in self.OFFICE_BROWSER_PARENTS and proc_name_lower in self.SUSPICIOUS_SHELL_CHILDREN:
            chain_str = f"{parent_name} [{ppid}] ──> {name} [{pid}]"
            return ProcessRuleResult(
                rule_name=self.rule_name,
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence,
                threat_type=self.threat_type,
                severity=ThreatSeverity.CRITICAL,
                description=f"High-risk application '{parent_name}' spawned shell/interpreter '{name}'",
                pid=pid,
                process_name=name,
                cmdline=cmdline,
                exe_path=exe_path,
                username=username,
                ppid=ppid,
                parent_name=parent_name,
                chain_summary=chain_str
            )

        # 2. Shell-to-Shell Evasion Chains (e.g. explorer -> powershell -> cmd or powershell -> cmd) (HIGH)
        if parent_name_lower in self.SHELL_NAMES and proc_name_lower in self.SHELL_NAMES:
            chain_str = f"{parent_name} [{ppid}] ──> {name} [{pid}]"
            return ProcessRuleResult(
                rule_name=self.rule_name,
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence,
                threat_type=self.threat_type,
                severity=ThreatSeverity.HIGH,
                description=f"Shell-to-shell evasion chain detected: '{parent_name}' spawned '{name}'",
                pid=pid,
                process_name=name,
                cmdline=cmdline,
                exe_path=exe_path,
                username=username,
                ppid=ppid,
                parent_name=parent_name,
                chain_summary=chain_str
            )

        # 3. Multi-level process tree lineage check (e.g. 3+ level chain ending in shell/LOLBin)
        if process_ancestors and len(process_ancestors) >= 2:
            ancestor_names = [a.get("name", "unknown") for a in process_ancestors]
            full_chain = " ──> ".join(ancestor_names + [name])

            # Check if explorer.exe -> shell -> shell / utility
            if "explorer.exe" in ancestor_names[0].lower() and proc_name_lower in self.SUSPICIOUS_SHELL_CHILDREN:
                return ProcessRuleResult(
                    rule_name=self.rule_name,
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    mitre_attack=self.mitre_attack,
                    confidence=self.confidence,
                    threat_type=self.threat_type,
                    severity=ThreatSeverity.HIGH,
                    description=f"Deep process lineage chain anomaly detected: {full_chain}",
                    pid=pid,
                    process_name=name,
                    cmdline=cmdline,
                    exe_path=exe_path,
                    username=username,
                    ppid=ppid,
                    parent_name=parent_name,
                    chain_summary=full_chain
                )

        return None
