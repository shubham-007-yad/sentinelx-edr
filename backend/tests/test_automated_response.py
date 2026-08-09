import os
import pytest
from app.detection.behavior.session import ProcessBehaviorSession
from app.detection.behavior.scoring import RansomwareCorrelationScorer
from app.detection.behavior.response_handler import (
    RansomwareResponseEngine,
    AutomatedResponsePolicy
)


def test_automated_response_containment_pipeline():
    session = ProcessBehaviorSession(
        device_id="DEV-PROD-007",
        pid=9120,
        process_name="lockbit_worker.exe"
    )

    # Add high risk ransomware behaviors
    for i in range(10):
        session.add_event({
            "event_type": "FILE_RENAMED",
            "old_path": f"/tmp/test_doc_{i}.docx",
            "new_path": f"/tmp/test_doc_{i}.docx.locked"
        })
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/tmp/test_doc_{i}.docx.locked",
            "raw_bytes": os.urandom(2048)
        })

    scorer = RansomwareCorrelationScorer()
    score_report = scorer.calculate_correlation_score(session)

    assert score_report.total_score >= 80

    # Execute automated response policy
    policy = AutomatedResponsePolicy(
        auto_suspend_process=True,
        auto_terminate_process=True,
        auto_isolate_endpoint=True,
        auto_quarantine_files=True,
        auto_notify_soc=True,
        trigger_score_threshold=80.0
    )

    engine = RansomwareResponseEngine(policy=policy)
    result = engine.handle_incident(session, score_report)

    assert result.status == "CONTAINED"
    assert result.is_process_suspended is True
    assert result.is_process_terminated is True
    assert result.is_endpoint_isolated is True
    assert result.soc_notified is True
    assert len(result.actions_executed) == 5

    action_types = [a["action_type"] for a in result.actions_executed]
    assert "SUSPEND_PROCESS" in action_types
    assert "TERMINATE_PROCESS" in action_types
    assert "ISOLATE" in action_types
    assert "QUARANTINE" in action_types
    assert "NOTIFY_SOC" in action_types


def test_automated_response_low_score_no_action():
    session = ProcessBehaviorSession(
        device_id="DEV-PROD-007",
        pid=1111,
        process_name="notepad.exe"
    )
    session.add_event({"event_type": "FILE_MODIFIED", "file_path": "/tmp/note.txt"})

    scorer = RansomwareCorrelationScorer()
    score_report = scorer.calculate_correlation_score(session)

    engine = RansomwareResponseEngine()
    result = engine.handle_incident(session, score_report)

    assert result.status == "NO_ACTION_REQUIRED"
    assert len(result.actions_executed) == 0
