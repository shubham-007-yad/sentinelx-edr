import os
import tempfile
import pytest
from quarantine_manager import QuarantineManager


def test_quarantine_file_metadata_tracking():
    with tempfile.TemporaryDirectory() as tmp_dir:
        quarantine_dir = os.path.join(tmp_dir, ".quarantine")
        sample_file = os.path.join(tmp_dir, "virus.exe")
        
        with open(sample_file, "w") as f:
            f.write("trojan horse payload content")

        original_path = os.path.abspath(sample_file)
        reason_msg = "Known Malware Signature - Ransomware"

        manager = QuarantineManager(quarantine_dir=quarantine_dir)
        record = manager.quarantine_file(
            file_path=original_path,
            reason=reason_msg
        )

        assert record is not None
        assert record.original_path == original_path
        assert os.path.exists(record.quarantine_path)
        assert not os.path.exists(original_path)
        assert record.sha256 != ""
        assert record.reason == reason_msg
        assert record.timestamp != ""

        # Verify Manifest Index
        records = manager.list_quarantined_files()
        assert len(records) == 1
        assert records[0].sha256 == record.sha256
        assert records[0].original_path == original_path
        assert records[0].quarantine_path == record.quarantine_path
        assert records[0].reason == reason_msg


def test_quarantine_file_get_by_hash():
    with tempfile.TemporaryDirectory() as tmp_dir:
        quarantine_dir = os.path.join(tmp_dir, ".quarantine")
        sample_file = os.path.join(tmp_dir, "autorun.inf")
        with open(sample_file, "w") as f:
            f.write("[autorun]\nopen=virus.exe")

        manager = QuarantineManager(quarantine_dir=quarantine_dir)
        record = manager.quarantine_file(sample_file, reason="Autorun script detected")

        fetched = manager.get_record_by_hash(record.sha256)
        assert fetched is not None
        assert fetched.original_path == os.path.abspath(sample_file)
