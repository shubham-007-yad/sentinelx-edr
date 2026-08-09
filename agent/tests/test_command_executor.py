import os
import tempfile
import pytest
from command_executor import CommandExecutor, CommandExecutionResult


def test_command_executor_delete_file():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"malicious code")
        tmp_path = tmp.name

    assert os.path.exists(tmp_path)

    executor = CommandExecutor()
    res = executor.execute("DELETE_FILE", {"file_path": tmp_path})

    assert res.success is True
    assert "Successfully deleted" in res.message
    assert not os.path.exists(tmp_path)


def test_command_executor_delete_file_not_found():
    executor = CommandExecutor()
    res = executor.execute("DELETE_FILE", {"file_path": "/path/to/nonexistent/file.exe"})

    assert res.success is False
    assert "File not found" in res.message


def test_command_executor_quarantine_file():
    with tempfile.TemporaryDirectory() as tmp_dir:
        quarantine_dir = os.path.join(tmp_dir, "quarantine")
        sample_file = os.path.join(tmp_dir, "bad_payload.exe")
        with open(sample_file, "w") as f:
            f.write("virus payload")

        executor = CommandExecutor(quarantine_dir=quarantine_dir)
        res = executor.execute("QUARANTINE_FILE", {"file_path": sample_file})

        assert res.success is True
        assert "Successfully quarantined" in res.message
        assert not os.path.exists(sample_file)
        
        quarantined_files = [f for f in os.listdir(quarantine_dir) if f != "manifest.json"]
        assert len(quarantined_files) == 1
        assert "bad_payload.exe" in quarantined_files[0]


def test_command_executor_isolate_device():
    executor = CommandExecutor()
    res = executor.execute("ISOLATE_DEVICE")

    assert res.success is True
    assert "isolation enabled" in res.message


def test_command_executor_start_scan():
    class DummyUSBService:
        def __init__(self):
            self.scanned = False
        def scan_and_detect(self):
            self.scanned = True

    dummy = DummyUSBService()
    executor = CommandExecutor(usb_service=dummy)
    res = executor.execute("START_SCAN", {"drive_letter": "/dev/sdb1"})

    assert res.success is True
    assert dummy.scanned is True
    assert "Triggered manual scan" in res.message
