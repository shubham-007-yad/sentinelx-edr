import os
import sys
import time
from collections import deque
from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class FIMFinding:
    rule_id: str
    rule_name: str
    threat_type: str
    severity: str  # HIGH, CRITICAL
    description: str
    remediation: str
    file_path: str
    file_name: str
    event_type: str


class FIMDetectionEngine:
    """
    Day 11 Phase 4 — FIM Detection Rules Engine
    Evaluates real-time file events against heuristic rules:
    1. Executable appears in Downloads (HIGH)
    2. Office document double extension masquerade (CRITICAL)
    3. Startup / Autostart folder modification (HIGH)
    4. Mass file modifications / Ransomware pattern (CRITICAL)
    """

    EXECUTABLE_EXTENSIONS = {
        ".exe", ".elf", ".bin", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".com", ".pif", ".sh", ".cpl", ".hta"
    }

    DOC_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt",
        ".rtf", ".jpg", ".png", ".zip", ".rar", ".7z"
    }

    STARTUP_PATH_KEYWORDS = [
        "startup", "autostart", "/etc/init.d", "/etc/systemd/system",
        "/etc/cron", "runonce", "currentversion\\run"
    ]

    def __init__(self, mass_threshold: int = 10, mass_window_seconds: float = 10.0):
        self.mass_threshold = mass_threshold
        self.mass_window_seconds = mass_window_seconds
        self.event_timestamps: deque = deque()

    def evaluate_event(self, event_payload: Dict[str, Any]) -> List[FIMFinding]:
        findings: List[FIMFinding] = []

        file_path = os.path.abspath(event_payload.get("file_path", ""))
        file_name = event_payload.get("file_name", os.path.basename(file_path)).lower()
        path_lower = file_path.lower()
        event_type = event_payload.get("event_type", "MODIFIED")
        is_executable = event_payload.get("is_executable", False)
        ext = os.path.splitext(file_name)[1]

        # Check mass file modification threshold
        now = time.time()
        self.event_timestamps.append(now)

        # Evict timestamps outside sliding window
        while self.event_timestamps and (now - self.event_timestamps[0] > self.mass_window_seconds):
            self.event_timestamps.popleft()

        # 1. Mass File Modifications Rule (CRITICAL)
        if len(self.event_timestamps) >= self.mass_threshold:
            count = len(self.event_timestamps)
            findings.append(FIMFinding(
                rule_id="RULE_FIM_004",
                rule_name="Mass File Modification (Ransomware Activity)",
                threat_type="FIM_MASS_FILE_MODIFICATION",
                severity="CRITICAL",
                description=f"Mass filesystem modifications detected: {count} file events within {self.mass_window_seconds}s window.",
                remediation="Immediately isolate endpoint device and inspect active processes for ransomware activity.",
                file_path=file_path,
                file_name=file_name,
                event_type=event_type
            ))

        # 2. Double Extension Masquerade Rule (CRITICAL)
        parts = file_name.split(".")
        if len(parts) >= 3:
            penultimate_ext = f".{parts[-2]}"
            final_ext = f".{parts[-1]}"
            if penultimate_ext in self.DOC_EXTENSIONS and (final_ext in self.EXECUTABLE_EXTENSIONS or is_executable):
                findings.append(FIMFinding(
                    rule_id="RULE_FIM_002",
                    rule_name="Office Document Double Extension Masquerade",
                    threat_type="FIM_DOUBLE_EXTENSION_MASQUERADE",
                    severity="CRITICAL",
                    description=f"File '{file_name}' disguises executable binary with document extension ({penultimate_ext}{final_ext}).",
                    remediation="Quarantine binary immediately and block process launch.",
                    file_path=file_path,
                    file_name=file_name,
                    event_type=event_type
                ))

        # 3. Startup Folder Modification Rule (HIGH)
        is_startup = any(k in path_lower for k in self.STARTUP_PATH_KEYWORDS)
        if is_startup and event_type in ["CREATED", "MODIFIED", "RENAMED"]:
            findings.append(FIMFinding(
                rule_id="RULE_FIM_003",
                rule_name="Startup Autostart Location Modification",
                threat_type="FIM_STARTUP_MODIFICATION",
                severity="HIGH",
                description=f"File event ({event_type}) in persistent autostart path: {file_path}",
                remediation="Verify autorun legitimacy and inspect persistent registry/cron entries.",
                file_path=file_path,
                file_name=file_name,
                event_type=event_type
            ))

        # 4. Executable Appears in Downloads Rule (HIGH)
        is_in_downloads = ("downloads" in path_lower or "/downloads" in path_lower or "\\downloads" in path_lower)
        is_exec_file = (ext in self.EXECUTABLE_EXTENSIONS) or is_executable
        if is_in_downloads and is_exec_file and event_type in ["CREATED", "MODIFIED", "RENAMED"]:
            findings.append(FIMFinding(
                rule_id="RULE_FIM_001",
                rule_name="Executable Dropped in Downloads Directory",
                threat_type="FIM_EXECUTABLE_IN_DOWNLOADS",
                severity="HIGH",
                description=f"Executable binary or script '{file_name}' created or modified in Downloads directory.",
                remediation="Analyze file signature, scan hash, and block unauthorized installer execution.",
                file_path=file_path,
                file_name=file_name,
                event_type=event_type
            ))

        return findings
