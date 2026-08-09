import time
import pytest
from app.detection.behavior.aggregator import ProcessFileAggregator


def test_process_file_aggregator_basic():
    agg = ProcessFileAggregator(pid=1024, process_name="test_proc.exe", default_window_seconds=30.0)

    # 1. Record 500 file modifications over 30s
    start_ts = time.time() - 10.0  # 10s ago
    for i in range(500):
        agg.record_change(
            change_type="MODIFIED",
            path=f"/home/user/Documents/doc_{i}.docx",
            old_hash=f"old_hash_{i}",
            new_hash=f"new_hash_{i}",
            timestamp=start_ts + (i * 0.01)
        )

    # 2. Record 10 file renames with extension change (.docx -> .docx.locked)
    for i in range(10):
        agg.record_change(
            change_type="RENAMED",
            path=f"/home/user/Documents/doc_{i}.docx",
            old_path=f"/home/user/Documents/doc_{i}.docx",
            new_path=f"/home/user/Documents/doc_{i}.docx.locked",
            timestamp=start_ts + 5.0
        )

    # 3. Record 5 file creations
    for i in range(5):
        agg.record_change(
            change_type="CREATED",
            path=f"/home/user/Documents/READ_ME_{i}.txt",
            timestamp=start_ts + 6.0
        )

    # 4. Record 5 file deletions
    for i in range(5):
        agg.record_change(
            change_type="DELETED",
            path=f"/home/user/Documents/orig_{i}.pdf",
            timestamp=start_ts + 7.0
        )

    summary = agg.get_summary(window_seconds=30.0)

    assert summary["pid"] == 1024
    assert summary["process_name"] == "test_proc.exe"
    assert summary["counts"]["modified"] == 500
    assert summary["counts"]["renamed"] == 10
    assert summary["counts"]["created"] == 5
    assert summary["counts"]["deleted"] == 5
    assert summary["counts"]["sha_changes"] == 500
    assert summary["extension_changes"].get(".docx->.locked") == 10
    
    # 500 files modified in 30 seconds -> modification_rate = 16.67 files/sec
    assert summary["rates_per_second"]["modification_rate"] >= 16.0
    assert summary["is_mass_modification_burst"] is True


def test_window_pruning():
    agg = ProcessFileAggregator(pid=2048, process_name="old_proc.exe", default_window_seconds=10.0)

    old_ts = time.time() - 40.0  # 40s ago (outside 10s window)
    new_ts = time.time() - 2.0   # 2s ago (inside 10s window)

    # Old records
    agg.record_change(change_type="MODIFIED", path="/tmp/old.txt", timestamp=old_ts)
    agg.record_change(change_type="CREATED", path="/tmp/old_create.txt", timestamp=old_ts)

    # Recent record
    agg.record_change(change_type="MODIFIED", path="/tmp/recent.txt", timestamp=new_ts)

    summary = agg.get_summary(window_seconds=10.0)

    assert summary["counts"]["modified"] == 1
    assert summary["counts"]["created"] == 0
    assert len(agg.records) == 1
