import uuid
import pytest
from unittest.mock import MagicMock, patch
from detectors.usb_detector import USBDeviceDetails, MockUSBDetector, USBDetectorService
from api import APIClient
import requests


def test_agent_usb_event_automatic_upload():
    mock_detector = MockUSBDetector()
    usb_service = USBDetectorService(detector=mock_detector)

    client = APIClient(backend_url="http://localhost:8000/api/v1")
    client.device_id = str(uuid.uuid4())

    uploaded_events = []

    def mock_send_usb_event(event_dict):
        uploaded_events.append(event_dict)
        return {"id": str(uuid.uuid4()), "status": "recorded"}

    client.send_usb_event = MagicMock(side_effect=mock_send_usb_event)

    def on_usb_event(event):
        client.send_usb_event(event.to_dict())

    usb_service.event_listener.register_callback(on_usb_event)

    # Plug in USB
    mock_detector.plug_in(USBDeviceDetails(
        drive_letter="E:",
        volume_label="SENTINEL_USB",
        filesystem="FAT32",
        total_size=16000000000,
        free_space=8000000000,
        serial_number="SN-TEST-100"
    ))

    events = usb_service.scan_and_detect()
    assert len(events) == 1
    assert len(uploaded_events) == 1
    assert uploaded_events[0]["drive_letter"] == "E:"
    assert uploaded_events[0]["event_type"] == "INSERT"
    assert uploaded_events[0]["volume_label"] == "SENTINEL_USB"


def test_send_usb_event_network_retry():
    client = APIClient(backend_url="http://localhost:8000/api/v1")
    client.device_id = str(uuid.uuid4())

    mock_response_fail = MagicMock()
    mock_response_fail.status_code = 503
    mock_response_fail.text = "Service Unavailable"

    mock_response_success = MagicMock()
    mock_response_success.status_code = 201
    mock_response_success.json.return_value = {"id": str(uuid.uuid4()), "event_type": "INSERT"}

    # Fail twice with RequestException, then succeed
    with patch.object(client.session, "post") as mock_post:
        mock_post.side_effect = [
            requests.exceptions.ConnectionError("Connection failed"),
            requests.exceptions.Timeout("Timeout error"),
            mock_response_success
        ]

        event_payload = {
            "event_type": "INSERT",
            "drive_letter": "F:",
            "volume_label": "RETRY_USB"
        }

        result = client.send_usb_event(event_payload, max_retries=3, initial_delay=0.01)

        assert result is not None
        assert result["event_type"] == "INSERT"
        assert mock_post.call_count == 3
