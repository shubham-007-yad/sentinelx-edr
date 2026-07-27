import os
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass


@dataclass
class AgentThreatFinding:
    threat_name: str
    threat_type: str
    severity: str
    description: str
    remediation: str


class AgentThreatEngine:
    """
    Agent-side Threat Detection Engine for local heuristic analysis
    on USB removable media before or during backend upload.
    """

    KNOWN_MALWARE_HASHES: Set[str] = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
        "44d88612fea8a8f36de82e1278abb02f",
        "685848866762e847c94fae75878848d7",
        "badc0de000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
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
    ) -> List[AgentThreatFinding]:
        findings: List[AgentThreatFinding] = []
        name_lower = file_name.lower()
        path_lower = full_path.lower()
        ext_clean = (extension.lower() if extension else "").strip()
        if ext_clean and not ext_clean.startswith("."):
            ext_clean = f".{ext_clean}"
        sha_lower = sha256.lower()

        # 1. Known Malicious SHA-256 Hash Matching
        if sha_lower in self.malware_hashes:
            findings.append(AgentThreatFinding(
                threat_name="Known Malicious Signature Detected",
                threat_type="KNOWN_MALWARE",
                severity="CRITICAL",
                description=f"File '{file_name}' SHA-256 hash ({sha256}) matches known malware signature.",
                remediation="Isolate endpoint and immediately delete or quarantine the file."
            ))

        # 2. Deceptive Double Extension Detection
        parts = name_lower.split(".")
        if len(parts) >= 3:
            penultimate_ext = f".{parts[-2]}"
            final_ext = f".{parts[-1]}"
            if penultimate_ext in self.DOC_IMAGE_EXTENSIONS and final_ext in self.EXECUTABLE_EXTENSIONS:
                findings.append(AgentThreatFinding(
                    threat_name="Deceptive Double Extension Executable",
                    threat_type="DOUBLE_EXTENSION",
                    severity="CRITICAL",
                    description=f"File '{file_name}' uses dual extension spoofing ({penultimate_ext}{final_ext}) to mask executable payload.",
                    remediation="Block execution and quarantine file immediately."
                ))

        # 3. Hidden Executable or Script File
        is_dotfile = name_lower.startswith(".") and len(name_lower) > 1
        if (is_hidden or is_dotfile) and (ext_clean in self.EXECUTABLE_EXTENSIONS):
            findings.append(AgentThreatFinding(
                threat_name="Hidden Executable File",
                threat_type="HIDDEN_EXECUTABLE",
                severity="HIGH",
                description=f"Executable binary or script '{file_name}' has hidden file attribute set on USB media.",
                remediation="Inspect origin of file and block payload execution."
            ))

        # 4. USB AutoRun Script Configuration
        if name_lower == "autorun.inf" or "autorun.inf" in path_lower or name_lower.startswith("autorun."):
            findings.append(AgentThreatFinding(
                threat_name="USB AutoRun Configuration Script",
                threat_type="AUTORUN_SCRIPT",
                severity="HIGH",
                description=f"USB AutoRun configuration '{file_name}' detected on removable media.",
                remediation="Disable USB AutoRun / AutoPlay via Group Policy."
            ))

        # 5. Suspicious Script Executables on Removable Storage
        if ext_clean in self.SCRIPT_EXTENSIONS:
            findings.append(AgentThreatFinding(
                threat_name="Suspicious Script Payload on USB",
                threat_type="SUSPICIOUS_EXTENSION",
                severity="HIGH",
                description=f"Potentially dangerous script format ({ext_clean}) found on removable USB storage media.",
                remediation="Restrict script execution from removable drives."
            ))

        # 6. Anomalous System Process Name on USB
        if name_lower in self.ANOMALOUS_SYSTEM_NAMES:
            findings.append(AgentThreatFinding(
                threat_name="Anomalous System Process Executable Name",
                threat_type="ANOMALOUS_FILE",
                severity="HIGH",
                description=f"File '{file_name}' matches critical OS process name but is present on removable media.",
                remediation="Verify binary signature or isolate device."
            ))

        return findings
