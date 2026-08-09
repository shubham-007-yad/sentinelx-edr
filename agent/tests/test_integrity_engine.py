import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from integrity_engine import AgentIntegrityEngine


def test_agent_integrity_engine_diff():
    engine = AgentIntegrityEngine()

    baseline_data = [
        {
            "file_path": "/etc/ssh/sshd_config",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size": 1000,
            "is_executable": False,
            "owner": "root"
        }
    ]
    engine.set_baseline(baseline_data)

    # 1. Test unchanged event
    event_same = {
        "event_type": "MODIFIED",
        "file_path": "/etc/ssh/sshd_config",
        "file_name": "sshd_config",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size": 1000,
        "is_executable": False
    }
    result_same = engine.process_file_event(event_same)
    assert result_same["is_changed"] is False
    assert result_same["status"] == "UNCHANGED"

    # 2. Test modified event (SHA mismatch + size mismatch)
    event_mod = {
        "event_type": "MODIFIED",
        "file_path": "/etc/ssh/sshd_config",
        "file_name": "sshd_config",
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "size": 1200,
        "is_executable": True
    }
    result_mod = engine.process_file_event(event_mod)
    assert result_mod["is_changed"] is True
    assert result_mod["status"] == "CHANGED"
    assert "sha256_mismatch" in result_mod["changes_detected"]
    assert "size_mismatch" in result_mod["changes_detected"]
    assert "executable_permission_changed" in result_mod["changes_detected"]

    # 3. Test untracked new file
    event_new = {
        "event_type": "CREATED",
        "file_path": "/etc/cron.d/malicious_cron",
        "file_name": "malicious_cron",
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "size": 300,
        "is_executable": True
    }
    result_new = engine.process_file_event(event_new)
    assert result_new["is_changed"] is True
    assert result_new["status"] == "NEW_FILE"
    assert "untracked_file_created" in result_new["changes_detected"]
