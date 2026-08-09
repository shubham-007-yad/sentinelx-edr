import pytest
from command_channel import AgentCommandChannel
from command_executor import CommandExecutor


class MockAPIClient:
    def __init__(self):
        self.reported_actions = []

    def report_command_status(self, action_id: str, status: str, result: str):
        self.reported_actions.append({
            "action_id": action_id,
            "status": status,
            "result": result
        })


def test_command_channel_process_isolate():
    mock_client = MockAPIClient()
    channel = AgentCommandChannel(api_client=mock_client)

    payload = {
        "event": "RESPONSE_COMMAND",
        "data": {
            "action_id": "action-1234",
            "device_id": "device-5678",
            "action_type": "ISOLATE_DEVICE"
        }
    }

    res = channel.process_incoming_command(payload)
    assert res.success is True
    assert "isolation enabled" in res.message

    assert len(mock_client.reported_actions) == 1
    assert mock_client.reported_actions[0]["action_id"] == "action-1234"
    assert mock_client.reported_actions[0]["status"] == "SUCCESS"


def test_command_channel_process_quarantine(tmp_path):
    bad_file = tmp_path / "threat.exe"
    bad_file.write_text("malware")

    mock_client = MockAPIClient()
    quarantine_dir = tmp_path / "quarantine"
    executor = CommandExecutor(quarantine_dir=str(quarantine_dir))
    channel = AgentCommandChannel(api_client=mock_client, executor=executor)

    payload = {
        "event": "RESPONSE_COMMAND",
        "data": {
            "action_id": "act-quarantine-1",
            "action_type": "QUARANTINE_FILE",
            "file_path": str(bad_file)
        }
    }

    res = channel.process_incoming_command(payload)
    assert res.success is True
    assert not bad_file.exists()
    assert len(mock_client.reported_actions) == 1
    assert mock_client.reported_actions[0]["status"] == "SUCCESS"


def test_command_channel_process_start_scan():
    class DummyScanService:
        def __init__(self):
            self.triggered = False
        def scan_and_detect(self):
            self.triggered = True

    dummy_service = DummyScanService()
    executor = CommandExecutor(usb_service=dummy_service)
    channel = AgentCommandChannel(executor=executor)

    payload = {
        "event": "RESPONSE_COMMAND",
        "data": {
            "action_id": "act-scan-1",
            "action_type": "START_SCAN",
            "drive_letter": "/dev/sdb1"
        }
    }

    res = channel.process_incoming_command(payload)
    assert res.success is True
    assert dummy_service.triggered is True
