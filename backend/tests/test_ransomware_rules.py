import os
import pytest
from app.detection.behavior.session import ProcessBehaviorSession
from app.detection.rules.ransomware_rules import (
    MassFileModificationRule,
    MassExtensionRenameRule,
    EntropyIncreaseRule,
    DeleteOriginalAfterRewriteRule,
    KnownRansomwareExtensionRule,
    RansomwareRuleEngine
)


def test_rule1_mass_file_modification():
    session = ProcessBehaviorSession(pid=1001, process_name="encryptor.exe")
    # Simulate 300 file modifications in 20 seconds
    for i in range(300):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/docs/file_{i}.docx"
        })

    rule = MassFileModificationRule(threshold_count=300, window_seconds=20.0)
    result = rule.evaluate_session(session)

    assert result is not None
    assert result.rule_id == "RANSOM_MASS_MODIFICATION"
    assert result.severity.value == "CRITICAL"
    assert result.score >= 90


def test_rule2_mass_extension_rename():
    session = ProcessBehaviorSession(pid=1002, process_name="renamer.exe")
    for i in range(15):
        session.add_event({
            "event_type": "FILE_RENAMED",
            "old_path": f"/docs/file_{i}.docx",
            "new_path": f"/docs/file_{i}.docx.locked"
        })

    rule = MassExtensionRenameRule(threshold_renames=10)
    result = rule.evaluate_session(session)

    assert result is not None
    assert result.rule_id == "RANSOM_MASS_EXTENSION_RENAME"
    assert result.severity.value == "CRITICAL"


def test_rule3_entropy_increase():
    session = ProcessBehaviorSession(pid=1003, process_name="cipher.exe")
    # Add 6 high-entropy events
    for i in range(6):
        session.add_event({
            "event_type": "FILE_MODIFIED",
            "file_path": f"/docs/data_{i}.bin",
            "raw_bytes": os.urandom(2048)
        })

    rule = EntropyIncreaseRule(entropy_threshold=7.5, min_high_entropy_files=5)
    result = rule.evaluate_session(session)

    assert result is not None
    assert result.rule_id == "RANSOM_ENTROPY_INCREASE"
    assert result.severity.value == "CRITICAL"
    assert result.details["high_entropy_count"] >= 5


def test_rule4_delete_original_after_rewrite():
    session = ProcessBehaviorSession(pid=1004, process_name="wiper.exe")
    for i in range(10):
        session.add_event({
            "event_type": "FILE_CREATED",
            "file_path": f"/docs/temp_{i}.tmp"
        })
        session.add_event({
            "event_type": "FILE_DELETED",
            "file_path": f"/docs/orig_{i}.docx"
        })

    rule = DeleteOriginalAfterRewriteRule(min_deletions=5, min_ratio=0.5)
    result = rule.evaluate_session(session)

    assert result is not None
    assert result.rule_id == "RANSOM_DELETE_ORIGINAL_REWRITE"
    assert result.severity.value == "HIGH"


def test_rule5_known_ransomware_extensions():
    session = ProcessBehaviorSession(pid=1005, process_name="lockbit.exe")
    session.add_event({
        "event_type": "FILE_RENAMED",
        "old_path": "/docs/important.pdf",
        "new_path": "/docs/important.pdf.lockbit"
    })

    rule = KnownRansomwareExtensionRule()
    result = rule.evaluate_session(session)

    assert result is not None
    assert result.rule_id == "RANSOM_KNOWN_EXTENSION"
    assert result.severity.value == "CRITICAL"
    assert result.score == 100


def test_ransomware_rule_engine():
    session = ProcessBehaviorSession(pid=1006, process_name="full_attack.exe")
    # Simulate full attack sequence
    for i in range(10):
        session.add_event({
            "event_type": "FILE_RENAMED",
            "old_path": f"/docs/doc_{i}.docx",
            "new_path": f"/docs/doc_{i}.docx.crypto",
            "raw_bytes": os.urandom(1024)
        })
        session.add_event({
            "event_type": "FILE_DELETED",
            "file_path": f"/docs/doc_{i}.docx"
        })

    engine = RansomwareRuleEngine()
    results = engine.evaluate_all(session)

    assert len(results) >= 3
    rule_ids = [r.rule_id for r in results]
    assert "RANSOM_KNOWN_EXTENSION" in rule_ids
    assert "RANSOM_MASS_EXTENSION_RENAME" in rule_ids
