import json
import os
import tempfile
import pytest
from file_metadata import FileMetadataCollector, collect_file_metadata, get_file_metadata_json


def test_file_metadata_collector_normal_file():
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"0" * 1024)
        tmp_path = tmp.name

    try:
        collector = FileMetadataCollector()
        metadata = collector.collect(tmp_path)

        assert metadata is not None
        assert metadata["file_name"] == os.path.basename(tmp_path)
        assert metadata["extension"] == ".exe"
        assert metadata["full_path"] == os.path.abspath(tmp_path)
        assert metadata["size"] == 1024
        assert metadata["file_size"] == 1024
        assert metadata["hidden"] is False
        assert metadata["is_hidden"] is False
        assert metadata["created_at"] is not None
        assert metadata["modified_at"] is not None
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_file_metadata_collector_hidden_dotfile():
    with tempfile.TemporaryDirectory() as tmpdir:
        hidden_path = os.path.join(tmpdir, ".secret_data")
        with open(hidden_path, "w") as f:
            f.write("top secret")

        collector = FileMetadataCollector()
        metadata = collector.collect(hidden_path)

        assert metadata is not None
        assert metadata["file_name"] == ".secret_data"
        assert metadata["hidden"] is True
        assert metadata["is_hidden"] is True


def test_file_metadata_json_serialization():
    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
        tmp.write(b"DOCX DATA")
        tmp_path = tmp.name

    try:
        json_str = get_file_metadata_json(tmp_path)
        assert json_str is not None
        data = json.loads(json_str)

        assert data["file_name"] == os.path.basename(tmp_path)
        assert data["extension"] == ".docx"
        assert data["size"] == 9
        assert "created_at" in data
        assert "modified_at" in data
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_file_metadata_non_existent_file():
    collector = FileMetadataCollector()
    metadata = collector.collect("/path/does/not/exist/sample.bin")
    assert metadata is None
