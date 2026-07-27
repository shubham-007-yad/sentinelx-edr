from typing import Dict, List, Optional, Any, Union
from app.models.threat import ThreatSeverity, ThreatType


class ThreatScorer:
    """
    Centralized Threat Scoring & Severity Resolution System for SentinelX EDR.
    Provides standard severity levels (LOW, MEDIUM, HIGH, CRITICAL), base score metrics,
    and configurable mappings for rules, file extensions, and composite file scoring.
    """

    # Default numeric point weights per severity level
    DEFAULT_SEVERITY_WEIGHTS: Dict[ThreatSeverity, int] = {
        ThreatSeverity.CRITICAL: 100,
        ThreatSeverity.HIGH: 75,
        ThreatSeverity.MEDIUM: 50,
        ThreatSeverity.LOW: 25,
    }

    # Default file extension severity mappings
    DEFAULT_EXTENSION_SEVERITIES: Dict[str, ThreatSeverity] = {
        # High risk executable and script formats
        ".exe": ThreatSeverity.HIGH,
        ".dll": ThreatSeverity.HIGH,
        ".bat": ThreatSeverity.HIGH,
        ".ps1": ThreatSeverity.HIGH,
        ".cmd": ThreatSeverity.HIGH,
        ".vbs": ThreatSeverity.HIGH,
        ".js": ThreatSeverity.HIGH,
        ".scr": ThreatSeverity.HIGH,
        ".sys": ThreatSeverity.HIGH,
        ".com": ThreatSeverity.HIGH,
        ".jse": ThreatSeverity.HIGH,
        ".vbe": ThreatSeverity.HIGH,
        ".wsf": ThreatSeverity.HIGH,
        ".wsh": ThreatSeverity.HIGH,
        ".hta": ThreatSeverity.HIGH,
        ".cpl": ThreatSeverity.HIGH,
        ".reg": ThreatSeverity.HIGH,
        ".lnk": ThreatSeverity.HIGH,
        ".pif": ThreatSeverity.HIGH,
    }

    # Default rule-level severity mappings
    DEFAULT_RULE_SEVERITIES: Dict[str, ThreatSeverity] = {
        "Known Malicious Signature Detected": ThreatSeverity.CRITICAL,
        "Double Extension Detection": ThreatSeverity.CRITICAL,
        "Deceptive Double Extension Executable": ThreatSeverity.CRITICAL,
        "Autorun Detection": ThreatSeverity.CRITICAL,
        "USB AutoRun Configuration Script": ThreatSeverity.CRITICAL,
        "Dangerous Extension Detection": ThreatSeverity.HIGH,
        "Hidden Executable File on Removable Media": ThreatSeverity.HIGH,
        "Hidden Executable File": ThreatSeverity.HIGH,
        "Anomalous System Process Masquerading": ThreatSeverity.HIGH,
        "Anomalous System Process Executable Name": ThreatSeverity.HIGH,
        "Suspicious Script Payload on USB": ThreatSeverity.HIGH,
    }

    def __init__(
        self,
        severity_weights: Optional[Dict[ThreatSeverity, int]] = None,
        extension_severities: Optional[Dict[str, ThreatSeverity]] = None,
        rule_severities: Optional[Dict[str, ThreatSeverity]] = None,
    ):
        self._severity_weights = (
            dict(severity_weights) if severity_weights else dict(self.DEFAULT_SEVERITY_WEIGHTS)
        )
        self._extension_severities = (
            dict(extension_severities)
            if extension_severities
            else dict(self.DEFAULT_EXTENSION_SEVERITIES)
        )
        self._rule_severities = (
            dict(rule_severities) if rule_severities else dict(self.DEFAULT_RULE_SEVERITIES)
        )

    def get_extension_severity(self, extension: str, default: ThreatSeverity = ThreatSeverity.MEDIUM) -> ThreatSeverity:
        """Resolves severity for a given file extension."""
        if not extension:
            return default
        ext_clean = extension.lower().strip()
        if not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"
        return self._extension_severities.get(ext_clean, default)

    def set_extension_severity(self, extension: str, severity: ThreatSeverity) -> None:
        """Dynamically configures severity for a file extension."""
        ext_clean = extension.lower().strip()
        if not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"
        self._extension_severities[ext_clean] = severity

    def get_rule_severity(self, rule_name: str, default: ThreatSeverity = ThreatSeverity.HIGH) -> ThreatSeverity:
        """Resolves severity for a given rule name."""
        return self._rule_severities.get(rule_name, default)

    def set_rule_severity(self, rule_name: str, severity: ThreatSeverity) -> None:
        """Dynamically configures severity for a rule name."""
        self._rule_severities[rule_name] = severity

    def get_severity_score(self, severity: Union[ThreatSeverity, str]) -> int:
        """Calculates numerical threat score for a severity level."""
        if isinstance(severity, str):
            try:
                severity_enum = ThreatSeverity(severity.upper())
            except ValueError:
                return 0
        else:
            severity_enum = severity
        return self._severity_weights.get(severity_enum, 0)

    def set_severity_weight(self, severity: ThreatSeverity, score: int) -> None:
        """Dynamically configures score weight for a severity level."""
        self._severity_weights[severity] = score

    def score_rule_finding(self, rule_name: str, fallback_severity: Optional[ThreatSeverity] = None) -> Dict[str, Any]:
        """Returns resolved severity and numeric threat score for a rule finding."""
        sev = self._rule_severities.get(rule_name, fallback_severity or ThreatSeverity.HIGH)
        score = self.get_severity_score(sev)
        return {"severity": sev, "score": score}

    def calculate_composite_score(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Calculates composite risk score and overall peak severity for a list of rule findings.
        """
        if not findings:
            return {
                "overall_severity": ThreatSeverity.LOW,
                "composite_score": 0,
                "findings_count": 0,
            }

        total_score = 0
        max_severity = ThreatSeverity.LOW
        severity_order = [
            ThreatSeverity.LOW,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.HIGH,
            ThreatSeverity.CRITICAL,
        ]

        for finding in findings:
            if hasattr(finding, "severity"):
                sev = finding.severity
                if isinstance(sev, str):
                    sev = ThreatSeverity(sev.upper())
            else:
                sev = ThreatSeverity.MEDIUM

            total_score += self.get_severity_score(sev)

            if severity_order.index(sev) > severity_order.index(max_severity):
                max_severity = sev

        # Cap composite score at 100 for overall metric calculation
        composite_score = min(total_score, 100)

        return {
            "overall_severity": max_severity,
            "composite_score": composite_score,
            "total_threat_points": total_score,
            "findings_count": len(findings),
        }

    def reset_to_defaults(self) -> None:
        """Resets all mappings and weights to factory defaults."""
        self._severity_weights = dict(self.DEFAULT_SEVERITY_WEIGHTS)
        self._extension_severities = dict(self.DEFAULT_EXTENSION_SEVERITIES)
        self._rule_severities = dict(self.DEFAULT_RULE_SEVERITIES)


# Global singleton instance for centralized access
threat_scorer = ThreatScorer()
