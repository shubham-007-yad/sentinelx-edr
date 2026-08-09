import os
import sys
import time
import shutil
import tempfile
import pytest

# Ensure agent directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collectors.file_watcher import RealTimeFileMonitor, get_default_monitored_directories


def test_default_directories_resolution():
    dirs = get_default_monitored_directories()
    assert isinstance(dirs, list)
    # Check home dir subpaths or valid returned strings
    for d in dirs:
        assert os.path.isabs(d)


def test_file_watcher_events():
    temp_dir = tempfile.mkdtemp(prefix="sentinelx_fim_test_")
    events_received = []

    def handle_event(evt):
        events_received.append(evt)

    monitor = RealTimeFileMonitor(watch_dirs=[temp_dir], callback=handle_event)
    monitor.start()

    try:
        # Give observer a brief moment to initialize
        time.sleep(0.5)

        # 1. Create file
        test_file = os.path.join(temp_dir, "fim_sample.txt")
        with open(test_file, "w") as f:
            f.write("Initial baseline content")

        time.sleep(1.0)

        # 2. Modify file
        with open(test_file, "a") as f:
            f.write("\nAppended suspicious line")

        time.sleep(1.0)

        # 3. Rename file
        renamed_file = os.path.join(temp_dir, "fim_renamed.txt")
        os.rename(test_file, renamed_file)

        time.sleep(1.0)

        # 4. Delete file
        os.remove(renamed_file)

        time.sleep(1.0)

    finally:
        monitor.stop()
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Validate received event types
    event_types = [e["event_type"] for e in events_received]
    assert "CREATED" in event_types
    assert "MODIFIED" in event_types or "RENAMED" in event_types or "DELETED" in event_types
    assert len(events_received) >= 2

    # Check payload fields
    created_events = [e for e in events_received if e["event_type"] == "CREATED"]
    if created_events:
        evt = created_events[0]
        assert "file_path" in evt
        assert "file_name" in evt
        assert "sha256" in evt
        assert "size" in evt
        assert "is_executable" in evt
