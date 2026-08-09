import os
import pytest
from app.detection.behavior.session import ProcessBehaviorSession
from app.detection.behavior.scoring import RansomwareCorrelationScorer


def test_correlation_score_combined_evidence():
    session = ProcessBehaviorSession(pid=9999, process_name="blackcat.exe")
    
    # 1. Mass Rename Evidence (10 renames with extension change -> 35 pts)
    for i in range(10):
        session.add_event({
            "event_type": "FILE_RENAMED",
            "old_path": f"/home/user/Documents/file_{i}.docx",
            "new_path": f"/home/user/Documents/file_{i}.docx.locked"
        })

    # 2. Entropy Increase Evidence (5 high entropy writes -> 30 pts)
    for i in range(5):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/home/user/Documents/file_{i}.docx.locked",
            "raw_bytes": os.urandom(2048)
        })

    # 3. Original Deletion Evidence (5 original file deletions -> 20 pts)
    for i in range(5):
        session.add_event({
            "event_type": "FILE_DELETED",
            "file_path": f"/home/user/Documents/file_{i}.docx"
        })

    # 4. High File Count / Velocity Evidence (50 file mutations total -> 15 pts)
    for i in range(35):
        session.add_event({
            "event_type": "FILE_CREATED",
            "file_path": f"/home/user/Documents/temp_{i}.tmp"
        })

    scorer = RansomwareCorrelationScorer(
        weight_mass_rename=35,
        weight_entropy_increase=30,
        weight_original_deletion=20,
        weight_high_file_count=15
    )
    
    report = scorer.calculate_correlation_score(session)

    assert report.total_score == 100
    assert report.severity.value == "CRITICAL"
    assert report.automated_isolation_recommended is True
    assert report.terminate_process_recommended is True
    
    indicators = [e.indicator for e in report.evidence_breakdown]
    assert "Mass rename" in indicators
    assert "Entropy increase" in indicators
    assert "Original deletion" in indicators
    assert "High file count" in indicators


def test_partial_correlation_score():
    session = ProcessBehaviorSession(pid=8888, process_name="suspicious_editor.exe")
    
    # Only modest file count mutations (no mass rename, no high entropy)
    for i in range(15):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/home/user/code/script_{i}.py"
        })

    scorer = RansomwareCorrelationScorer()
    report = scorer.calculate_correlation_score(session)

    assert report.total_score < 50
    assert report.severity.value in ["LOW", "MEDIUM"]
    assert report.automated_isolation_recommended is False
