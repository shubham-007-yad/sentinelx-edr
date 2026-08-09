import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detectors.fim_detector import FIMDetectionEngine


def test_fim_executable_in_downloads():
    engine = FIMDetectionEngine()

    evt = {
        "event_type": "CREATED",
        "file_path": "/home/user/Downloads/setup.exe",
        "file_name": "setup.exe",
        "is_executable": True
    }

    findings = engine.evaluate_event(evt)
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_FIM_001" in rule_ids
    match = next(f for f in findings if f.rule_id == "RULE_FIM_001")
    assert match.severity == "HIGH"
    assert match.threat_type == "FIM_EXECUTABLE_IN_DOWNLOADS"


def test_fim_office_double_extension():
    engine = FIMDetectionEngine()

    evt = {
        "event_type": "CREATED",
        "file_path": "/home/user/Documents/invoice.docx.exe",
        "file_name": "invoice.docx.exe",
        "is_executable": True
    }

    findings = engine.evaluate_event(evt)
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_FIM_002" in rule_ids
    match = next(f for f in findings if f.rule_id == "RULE_FIM_002")
    assert match.severity == "CRITICAL"
    assert match.threat_type == "FIM_DOUBLE_EXTENSION_MASQUERADE"


def test_fim_startup_modification():
    engine = FIMDetectionEngine()

    evt = {
        "event_type": "MODIFIED",
        "file_path": "/home/user/.config/autostart/malware.desktop",
        "file_name": "malware.desktop",
        "is_executable": True
    }

    findings = engine.evaluate_event(evt)
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_FIM_003" in rule_ids
    match = next(f for f in findings if f.rule_id == "RULE_FIM_003")
    assert match.severity == "HIGH"
    assert match.threat_type == "FIM_STARTUP_MODIFICATION"


def test_fim_mass_file_modification_ransomware():
    engine = FIMDetectionEngine(mass_threshold=5, mass_window_seconds=2.0)

    findings = []
    for i in range(6):
        evt = {
            "event_type": "MODIFIED",
            "file_path": f"/home/user/Documents/file_{i}.txt",
            "file_name": f"file_{i}.txt"
        }
        findings.extend(engine.evaluate_event(evt))

    rule_ids = [f.rule_id for f in findings]
    assert "RULE_FIM_004" in rule_ids
    match = next(f for f in findings if f.rule_id == "RULE_FIM_004")
    assert match.severity == "CRITICAL"
    assert match.threat_type == "FIM_MASS_FILE_MODIFICATION"
