import json
from collectors import USBMetadataCollector, collect_usb_metadata, get_usb_metadata_json


def test_usb_metadata_collector_single_drive():
    collector = USBMetadataCollector()
    data = collector.collect_drive("E:")

    assert isinstance(data, dict)
    assert data["drive_letter"] == "E:"
    assert "volume_label" in data
    assert "filesystem" in data
    assert "total_size" in data
    assert "free_space" in data
    assert "serial_number" in data
    assert "timestamp" in data


def test_usb_metadata_collector_json_payload():
    json_payload = get_usb_metadata_json(drive_letter="E:")
    assert isinstance(json_payload, str)

    parsed = json.loads(json_payload)
    assert parsed["drive_letter"] == "E:"
    assert "volume_label" in parsed
    assert "filesystem" in parsed
    assert "total_size" in parsed
    assert "free_space" in parsed
    assert "serial_number" in parsed
    assert "timestamp" in parsed


def test_usb_metadata_collector_collect_all():
    collector = USBMetadataCollector()
    all_data = collector.collect_all()
    assert isinstance(all_data, list)

    all_json = get_usb_metadata_json()
    assert isinstance(all_json, str)
    parsed = json.loads(all_json)
    assert isinstance(parsed, list)
