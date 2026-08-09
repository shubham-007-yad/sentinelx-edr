import os
import sys
import time
import pytest
from datetime import datetime, timezone

from app.detection.behavior.metrics import calculate_shannon_entropy
from app.detection.behavior.session import ProcessBehaviorSession
from app.detection.behavior.aggregator import ProcessFileAggregator
from app.detection.behavior.timeline import BehaviorTimeline
from app.detection.behavior.correlation import BehaviorCorrelationRules
from app.detection.behavior.scoring import RansomwareCorrelationScorer
from app.detection.rules.ransomware_rules import (
    MassFileModificationRule,
    MassExtensionRenameRule,
    EntropyIncreaseRule,
    DeleteOriginalAfterRewriteRule,
    KnownRansomwareExtensionRule,
    RansomwareRuleEngine
)
from app.detection.behavior.engine import BehaviorCorrelationEngine
from app.detection.behavior.response_handler import (
    RansomwareResponseEngine,
    AutomatedResponsePolicy
)
from app.detection.behavior.incident_correlator import IncidentCorrelationEngine
from app.api.ransomware import get_ransomware_summary, get_ransomware_incidents, get_ransomware_timeline


def test_validation_1_normal_document_editing_sanity():
    """Validate 1: Normal document editing (Sanity check — False positive test)."""
    session = ProcessBehaviorSession(pid=1234, process_name="winword.exe")
    
    # Modify 3 document files with normal plaintext
    for i in range(3):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/home/user/Documents/report_{i}.docx",
            "raw_bytes": f"This is normal document content for report {i}.".encode("utf-8")
        })

    scorer = RansomwareCorrelationScorer()
    report = scorer.calculate_correlation_score(session)

    assert report.total_score < 30
    assert report.severity.value == "LOW"
    assert report.automated_isolation_recommended is False


def test_validation_2_large_file_copy_sanity():
    """Validate 2: Large file copy (Bulk copy sanity check)."""
    session = ProcessBehaviorSession(pid=2345, process_name="robocopy.exe")
    
    # Create 20 files with standard content
    for i in range(20):
        session.add_event({
            "event_type": "FILE_CREATED",
            "file_path": f"/backup/drive/file_{i}.txt",
            "raw_bytes": f"Standard backup file payload content chunk {i}.".encode("utf-8")
        })

    scorer = RansomwareCorrelationScorer()
    report = scorer.calculate_correlation_score(session)

    assert report.total_score < 50
    assert report.severity.value in ["LOW", "MEDIUM"]
    assert report.automated_isolation_recommended is False


def test_validation_3_simulated_ransomware_behavior():
    """Validate 3: Simulated ransomware behavior (Full attack workflow)."""
    session = ProcessBehaviorSession(
        device_id="DEV-PROD-999",
        pid=6660,
        process_name="ransomware_sim.exe",
        command_line="vssadmin delete shadows /all /quiet"
    )

    # 1. Shadow copy wipe
    session.add_event({
        "event_type": "PROCESS_COMMAND",
        "command_line": "vssadmin delete shadows /all /quiet"
    })

    # 2. High entropy payload writes
    for i in range(10):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/data/file_{i}.docx",
            "raw_bytes": os.urandom(2048)
        })

    # 3. Extension swaps
    for i in range(10):
        session.add_event({
            "event_type": "FILE_RENAMED",
            "old_path": f"/data/file_{i}.docx",
            "new_path": f"/data/file_{i}.docx.locked"
        })

    # 4. Delete originals
    for i in range(5):
        session.add_event({
            "event_type": "FILE_DELETED",
            "file_path": f"/data/file_{i}.docx"
        })

    scorer = RansomwareCorrelationScorer()
    report = scorer.calculate_correlation_score(session)

    assert report.total_score == 100
    assert report.severity.value == "CRITICAL"
    assert session.status == "MALICIOUS_RANSOMWARE"


def test_validation_4_extension_changes():
    """Validate 4: Extension changes (Mass extension mutation test)."""
    session = ProcessBehaviorSession(pid=7710, process_name="extension_mutator.exe")
    
    for i in range(25):
        session.add_event({
            "event_type": "FILE_RENAMED",
            "old_path": f"/docs/file_{i}.pdf",
            "new_path": f"/docs/file_{i}.pdf.locked"
        })

    rule = MassExtensionRenameRule(threshold_renames=10)
    result = rule.evaluate_session(session)

    assert result is not None
    assert result.rule_id == "RANSOM_MASS_EXTENSION_RENAME"
    assert session.metrics.known_ransomware_ext_count == 25


def test_validation_5_mass_rename():
    """Validate 5: Mass rename (Rapid file renaming test)."""
    agg = ProcessFileAggregator(pid=8820, process_name="mass_renamer.exe", default_window_seconds=10.0)
    
    now_ts = time.time()
    for i in range(50):
        agg.record_change(
            change_type="RENAMED",
            path=f"/data/doc_{i}.docx",
            old_path=f"/data/doc_{i}.docx",
            new_path=f"/data/doc_{i}.docx.crypto",
            timestamp=now_ts + (i * 0.05)
        )

    summary = agg.get_summary(window_seconds=10.0)

    assert summary["counts"]["renamed"] == 50
    assert summary["rates_per_second"]["rename_rate"] >= 5.0


def test_validation_6_entropy_increase():
    """Validate 6: Entropy increase (High Shannon entropy payload test)."""
    plain_bytes = b"Hello world, normal document text."
    plain_entropy = calculate_shannon_entropy(plain_bytes)
    assert plain_entropy < 6.0

    enc_bytes = os.urandom(2048)
    enc_entropy = calculate_shannon_entropy(enc_bytes)
    assert enc_entropy >= 7.5

    session = ProcessBehaviorSession(pid=9910, process_name="entropy_tester.exe")
    for i in range(10):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/docs/enc_{i}.bin",
            "raw_bytes": os.urandom(1024)
        })

    rule = EntropyIncreaseRule(entropy_threshold=7.5, min_high_entropy_files=5)
    result = rule.evaluate_session(session)

    assert result is not None
    assert result.rule_id == "RANSOM_ENTROPY_INCREASE"
    assert result.details["high_entropy_count"] == 10


def test_validation_7_automatic_isolation():
    """Validate 7: Automatic isolation (Automated Response Engine Trigger test)."""
    session = ProcessBehaviorSession(
        device_id="DEV-CRITICAL-001",
        pid=9999,
        process_name="active_ransomware.exe"
    )

    for i in range(10):
        session.add_event({
            "event_type": "FILE_RENAMED",
            "old_path": f"/tmp/doc_{i}.docx",
            "new_path": f"/tmp/doc_{i}.docx.locked"
        })
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/tmp/doc_{i}.docx.locked",
            "raw_bytes": os.urandom(1024)
        })

    scorer = RansomwareCorrelationScorer()
    score_report = scorer.calculate_correlation_score(session)

    policy = AutomatedResponsePolicy(
        auto_suspend_process=True,
        auto_terminate_process=True,
        auto_isolate_endpoint=True,
        auto_quarantine_files=True,
        auto_notify_soc=True,
        trigger_score_threshold=80.0
    )

    resp_engine = RansomwareResponseEngine(policy=policy)
    execution_result = resp_engine.handle_incident(session, score_report)

    assert execution_result.status == "CONTAINED"
    assert execution_result.is_process_suspended is True
    assert execution_result.is_process_terminated is True
    assert execution_result.is_endpoint_isolated is True
    assert execution_result.soc_notified is True


def test_validation_8_timeline_generation():
    """Validate 8: Timeline generation (Chronological attack storyline trace test)."""
    engine = BehaviorCorrelationEngine()
    sim_pid = 4812
    device_id = "DEV-DESKTOP-8921"
    
    # 10:02 Mass modification
    engine.ingest_event({"device_id": device_id, "pid": sim_pid, "process_name": "vss_encryptor.exe", "event_type": "FILE_MODIFIED", "file_path": "/docs/file_1.docx"})
    # 10:03 Extensions changed
    engine.ingest_event({"device_id": device_id, "pid": sim_pid, "process_name": "vss_encryptor.exe", "event_type": "FILE_RENAMED", "old_path": "/docs/file_1.docx", "new_path": "/docs/file_1.docx.locked"})
    # 10:04 Critical Alert / Shadow copy wipe
    engine.ingest_event({"device_id": device_id, "pid": sim_pid, "process_name": "vss_encryptor.exe", "event_type": "PROCESS_COMMAND", "command_line": "vssadmin delete shadows /all /quiet"})

    session = engine.sessions[engine.pid_map[f"{device_id}:{sim_pid}"]]
    timeline = engine.get_session_timeline(session.session_id)

    assert timeline is not None
    assert timeline["total_steps"] >= 3
    event_types = [t["event_type"] for t in timeline["timeline"]]
    assert "FILE_MODIFIED" in event_types
    assert "FILE_RENAMED" in event_types


def test_validation_9_dashboard_rendering():
    """Validate 9: Dashboard rendering (Backend summary & incident API test)."""
    summary = get_ransomware_summary()
    assert "suspicious_processes" in summary
    assert "files_modified" in summary
    assert "endpoints_affected" in summary
    assert "critical_incidents" in summary

    incidents = get_ransomware_incidents()
    assert isinstance(incidents, list)
    assert len(incidents) >= 1

    timeline = get_ransomware_timeline("sim-session-001")
    assert "timeline" in timeline
    assert len(timeline["timeline"]) >= 4
