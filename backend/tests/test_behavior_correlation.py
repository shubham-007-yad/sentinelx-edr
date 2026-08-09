import pytest
from app.detection.behavior.metrics import calculate_shannon_entropy, BehavioralMetrics
from app.detection.behavior.session import ProcessBehaviorSession
from app.detection.behavior.timeline import BehaviorTimeline
from app.detection.behavior.correlation import BehaviorCorrelationRules
from app.detection.behavior.engine import BehaviorCorrelationEngine


def test_shannon_entropy_calculation():
    # Plain text should have low entropy (~ 3.5 - 4.5)
    plain_text = b"Hello world! This is a normal document file content with predictable characters."
    plain_entropy = calculate_shannon_entropy(plain_text)
    assert 0.0 < plain_entropy < 6.0

    # High entropy payload (pseudo-random / encrypted bytes) should be > 7.5
    import os
    random_bytes = os.urandom(4096)
    encrypted_entropy = calculate_shannon_entropy(random_bytes)
    assert encrypted_entropy >= 7.5


def test_behavioral_session_metrics():
    session = ProcessBehaviorSession(
        device_id="dev-123",
        pid=4096,
        process_name="ransomware_test.exe",
        command_line="vssadmin delete shadows /all /quiet"
    )

    # Ingest event 1: Shadow copy wipe
    res1 = session.add_event({
        "event_type": "PROCESS_COMMAND",
        "command_line": "vssadmin delete shadows /all /quiet"
    })
    assert session.metrics.shadow_copy_deleted is True

    # Ingest event 2: High entropy file modifications (5 files)
    import os
    for i in range(5):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/tmp/test_file_{i}.docx",
            "raw_bytes": os.urandom(2048)
        })
    assert session.metrics.high_entropy_count >= 5

    # Ingest event 3: Ransom note drops (2 directories)
    session.add_event({
        "event_type": "FILE_CREATED",
        "file_path": "/tmp/READ_ME.txt"
    })
    session.add_event({
        "event_type": "FILE_CREATED",
        "file_path": "/home/user/Documents/HOW_TO_DECRYPT.html"
    })
    assert session.metrics.ransom_note_count >= 2

    # Ingest event 4: Known ransomware extension rename
    session.add_event({
        "event_type": "FILE_RENAMED",
        "old_path": "/tmp/doc.docx",
        "new_path": "/tmp/doc.docx.locked"
    })
    assert session.metrics.known_ransomware_ext_count >= 1

    score = session.metrics.calculate_composite_risk_score()
    assert score >= 75.0
    assert session.metrics.severity == "CRITICAL"


def test_behavior_correlation_rules():
    session = ProcessBehaviorSession(
        device_id="dev-123",
        pid=5120,
        process_name="bad_actor.exe"
    )
    import os
    # Add 5 high entropy events
    for i in range(5):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/tmp/encrypted_doc_{i}.pdf",
            "raw_bytes": os.urandom(1024)
        })

    matches = BehaviorCorrelationRules.evaluate_all(session)
    assert len(matches) >= 1
    assert any(m.rule_id == "CORR_MASS_ENTROPY_BURST" for m in matches)


def test_behavior_engine_orchestration():
    engine = BehaviorCorrelationEngine()
    
    # Ingest events into engine
    result = engine.ingest_event({
        "device_id": "dev-999",
        "pid": 8888,
        "process_name": "wiper.exe",
        "cmd": "vssadmin delete shadows /all /quiet",
        "event_type": "PROCESS_COMMAND"
    })
    
    assert result["device_id"] == "dev-999"
    assert result["pid"] == 8888
    assert result["metrics"]["shadow_copy_deleted"] is True
    
    # Check session timeline
    timeline = engine.get_session_timeline(result["session_id"])
    assert timeline is not None
    assert timeline["total_steps"] >= 1
