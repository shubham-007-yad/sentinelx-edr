import ipaddress
from typing import Optional, Set
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.network.base import BaseNetworkRule, NetworkRuleResult


class UnexpectedInternetAccessRule(BaseNetworkRule):
    """
    Detects administrative binaries and script interpreters (e.g. powershell.exe, cmd.exe, certutil.exe)
    making direct outbound network connections to external public Internet IP addresses.
    Severity: HIGH.
    """

    rule_name: str = "Unexpected Internet Access"
    rule_id: str = "NET-RULE-0004"
    rule_version: str = "1.0.0"
    mitre_attack: str = "T1059"
    confidence: float = 90.0
    threat_type: ThreatType = ThreatType.UNEXPECTED_INTERNET_ACCESS
    severity: ThreatSeverity = ThreatSeverity.HIGH

    DEFAULT_TARGET_BINARIES: Set[str] = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "certutil.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "cscript.exe",
        "wscript.exe",
        "bitsadmin.exe"
    }

    def __init__(self, target_binaries: Optional[Set[str]] = None):
        if target_binaries is not None:
            self.target_binaries = {b.lower() for b in target_binaries}
        else:
            self.target_binaries = set(self.DEFAULT_TARGET_BINARIES)

    def _is_external_ip(self, ip_str: str) -> bool:
        if not ip_str or ip_str == "0.0.0.0":
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            # Flag if IP is global/public (not private, loopback, link-local, multicast, or reserved)
            return ip_obj.is_global
        except ValueError:
            return False

    def evaluate_connection(
        self,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_port: Optional[int] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        protocol: str = "TCP",
        state: Optional[str] = None
    ) -> Optional[NetworkRuleResult]:
        if not process_name or not remote_ip:
            return None

        clean_proc_name = process_name.lower().split("/")[-1].split("\\")[-1]

        if clean_proc_name in self.target_binaries and self._is_external_ip(remote_ip):
            desc = (
                f"Unexpected Internet Access: Administrative process '{process_name}' (PID {pid}) "
                f"connected directly to external public IP {remote_ip}:{remote_port} [{protocol}]."
            )
            return NetworkRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=desc,
                pid=pid,
                process_name=process_name,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                state=state,
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )

        return None
