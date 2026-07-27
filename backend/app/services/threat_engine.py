import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from app.models.threat_record import ThreatSeverity, ThreatType
from app.detection.scoring import threat_scorer


@dataclass
class ThreatFinding:
    threat_name: str
    threat_type: str
    severity: str
    description: str
    remediation: str
    score: int = field(default=0)

    def __post_init__(self):
        if self.score == 0 and self.severity:
            self.score = threat_scorer.get_severity_score(self.severity)


class ThreatDetectionEngine:
    """
    Threat Detection Engine for SentinelX EDR.
    Analyzes file scan records and metadata against signature databases,
    file attribute anomalies, extension heuristics, and dual extension spoofing patterns.
    """

    # Known Malicious SHA-256 Signatures
    KNOWN_MALWARE_HASHES: Set[str] = {
        # EICAR Test Hashes
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
        "44d88612fea8a8f36de82e1278abb02f",
        "685848866762e847c94fae75878848d7",
        # Demo / Simulated Malware Signatures
        "badc0de000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "1111111111111111111111111111111111111111111111111111111111111111"
    }

    EXECUTABLE_EXTENSIONS: Set[str] = {
        ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
        ".ps1", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".com", ".pif"
    }

    SCRIPT_EXTENSIONS: Set[str] = {
        ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".scr", ".hta", ".js", ".wsf", ".cpl", ".reg", ".lnk"
    }

    DOC_IMAGE_EXTENSIONS: Set[str] = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".csv", ".zip", ".rar", ".7z"
    }

    ANOMALOUS_SYSTEM_NAMES: Set[str] = {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
        "smss.exe", "winlogon.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "explorer.exe"
    }

    def __init__(self, custom_malware_hashes: Optional[Set[str]] = None):
        self.malware_hashes = set(self.KNOWN_MALWARE_HASHES)
        if custom_malware_hashes:
            self.malware_hashes.update(h.lower() for h in custom_malware_hashes)

    def analyze_file(
        self,
        file_name: str,
        full_path: str,
        extension: Optional[str],
        file_size: int,
        sha256: str,
        is_hidden: bool = False
    ) -> List[ThreatFinding]:
        """
        Runs comprehensive threat analysis on a single file scan record.
        Returns a list of ThreatFinding objects detected.
        """
        findings: List[ThreatFinding] = []
        name_lower = file_name.lower()
        path_lower = full_path.lower()
        ext_clean = (extension.lower() if extension else "").strip()
        if ext_clean and not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"
        sha_lower = sha256.lower()

        # 1. Known Malicious SHA-256 Hash Matching
        if sha_lower in self.malware_hashes:
            sev = threat_scorer.get_rule_severity("Known Malicious Signature Detected", ThreatSeverity.CRITICAL)
            findings.append(ThreatFinding(
                threat_name="Known Malicious Signature Detected",
                threat_type=ThreatType.KNOWN_MALWARE.value,
                severity=sev.value,
                description=f"File '{file_name}' SHA-256 hash ({sha256}) matches known malware signature in threat intelligence database.",
                remediation="Isolate endpoint and immediately delete or quarantine the file. Perform full system anti-virus scan."
            ))

        # 2. Deceptive Double Extension Detection (e.g. invoice.pdf.exe)
        parts = name_lower.split(".")
        if len(parts) >= 3:
            penultimate_ext = f".{parts[-2]}"
            final_ext = f".{parts[-1]}"
            if penultimate_ext in self.DOC_IMAGE_EXTENSIONS and final_ext in self.EXECUTABLE_EXTENSIONS:
                sev = threat_scorer.get_rule_severity("Deceptive Double Extension Executable", ThreatSeverity.CRITICAL)
                findings.append(ThreatFinding(
                    threat_name="Deceptive Double Extension Executable",
                    threat_type=ThreatType.DOUBLE_EXTENSION.value,
                    severity=sev.value,
                    description=f"File '{file_name}' uses dual extension spoofing ({penultimate_ext}{final_ext}) to mask executable payload as a document or image.",
                    remediation="Do NOT execute file. Block file execution via AppLocker/EDR policy and quarantine file."
                ))

        # 3. Hidden Executable or Script File
        is_dotfile = name_lower.startswith(".") and len(name_lower) > 1
        if (is_hidden or is_dotfile) and (ext_clean in self.EXECUTABLE_EXTENSIONS):
            sev = threat_scorer.get_rule_severity("Hidden Executable File", ThreatSeverity.HIGH)
            findings.append(ThreatFinding(
                threat_name="Hidden Executable File",
                threat_type=ThreatType.HIDDEN_EXECUTABLE.value,
                severity=sev.value,
                description=f"Executable binary or script '{file_name}' has hidden file attribute set on removable USB media.",
                remediation="Inspect origin of file, disable hidden file execution, and block payload."
            ))

        # 4. USB AutoRun Script Configuration
        if name_lower == "autorun.inf" or "autorun.inf" in path_lower or name_lower.startswith("autorun."):
            sev = threat_scorer.get_rule_severity("USB AutoRun Configuration Script", ThreatSeverity.CRITICAL)
            findings.append(ThreatFinding(
                threat_name="USB AutoRun Configuration Script",
                threat_type=ThreatType.AUTORUN_SCRIPT.value,
                severity=sev.value,
                description=f"USB AutoRun file '{file_name}' detected on removable media. Often leveraged by worms for automatic execution.",
                remediation="Disable USB AutoRun / AutoPlay via Group Policy (GPO) and inspect referenced autorun target files."
            ))

        # 5. Suspicious Script Executables on Removable Storage
        if ext_clean in self.SCRIPT_EXTENSIONS:
            sev = threat_scorer.get_extension_severity(ext_clean, ThreatSeverity.HIGH)
            findings.append(ThreatFinding(
                threat_name="Suspicious Script Payload on USB",
                threat_type=ThreatType.SUSPICIOUS_EXTENSION.value,
                severity=sev.value,
                description=f"Potentially dangerous script format ({ext_clean}) found on removable USB storage media.",
                remediation="Restrict execution of script hosts (wscript.exe, cscript.exe, powershell.exe) from removable drives."
            ))

        # 6. Anomalous System Process Name on USB
        if name_lower in self.ANOMALOUS_SYSTEM_NAMES:
            sev = threat_scorer.get_rule_severity("Anomalous System Process Executable Name", ThreatSeverity.HIGH)
            findings.append(ThreatFinding(
                threat_name="Anomalous System Process Executable Name",
                threat_type=ThreatType.ANOMALOUS_FILE.value,
                severity=sev.value,
                description=f"File '{file_name}' matches critical OS process name but is present on removable media, indicating masquerading.",
                remediation="Verify binary digital signature. If unsigned or mismatched hash, isolate device and quarantine."
            ))

        return findings
