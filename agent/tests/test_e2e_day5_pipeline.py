import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from background_scanner import USBScanPipelineWorker
from api.client import APIClient


def test_full_day5_scanning_pipeline_e2e():
    """
    Full Day 5 EDR Pipeline E2E Integration Test:
    USB Inserted -> Enumerate Files -> Collect Metadata -> Calculate SHA-256 -> Upload -> Backend Persisted.
    """
    test_client = TestClient(app)

    # 1. Setup DB Device & USB Event
    db = SessionLocal()
    try:
        device = Device(
            hostname="e2e-day5-host",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        usb_event = USBEvent(
            device_id=device.id,
            event_type=USBEventType.INSERT,
            drive_letter="E:",
            volume_label="E2E_DAY5_FLASH"
        )
        db.add(usb_event)
        db.commit()
        db.refresh(usb_event)

        event_id = str(usb_event.id)
    finally:
        db.close()

    # 2. Create mock USB filesystem
    with tempfile.TemporaryDirectory() as tmpdir:
        movies_dir = os.path.join(tmpdir, "Movies")
        office_dir = os.path.join(tmpdir, "Office")
        secret_dir = os.path.join(tmpdir, ".secret")
        os.makedirs(movies_dir)
        os.makedirs(office_dir)
        os.makedirs(secret_dir)

        f1 = os.path.join(movies_dir, "sample.mp4")
        f2 = os.path.join(office_dir, "report.docx")
        f3 = os.path.join(secret_dir, ".hidden_credentials")

        with open(f1, "wb") as f:
            f.write(b"VIDEO CONTENT " * 100)
        with open(f2, "wb") as f:
            f.write(b"WORD DOCUMENT DATA")
        with open(f3, "wb") as f:
            f.write(b"TOP SECRET HASH")

        # 3. Instantiate Agent APIClient & Scanner Worker
        # We wrap TestClient into a mock adapter for APIClient so requests hit FastAPI TestClient
        api_client = APIClient()

        # Mock session.post on api_client to route through TestClient
        def mock_post(url, json=None, timeout=None):
            endpoint = url.replace("http://localhost:8000", "") if "http://localhost:8000" in url else url
            resp = test_client.post(endpoint, json=json)
            class MockResponse:
                def __init__(self, status_code, json_data, text):
                    self.status_code = status_code
                    self._json = json_data
                    self.text = text
                def json(self):
                    return self._json
            return MockResponse(resp.status_code, resp.json(), resp.text)

        api_client.session.post = mock_post

        worker = USBScanPipelineWorker(api_client=api_client, batch_size=10)

        # 4. Execute automated scan task
        summary = worker.process_scan_task(usb_event_id=event_id, drive_letter=tmpdir)

        assert summary["scanned_count"] == 3
        assert summary["uploaded_count"] == 3

        # 5. Verify records stored in Backend Database via GET API
        get_resp = test_client.get(f"/api/v1/usb/scans?usb_event_id={event_id}")
        assert get_resp.status_code == 200
        scans_data = get_resp.json()
        assert len(scans_data) == 3

        file_names = [s["file_name"] for s in scans_data]
        assert "sample.mp4" in file_names
        assert "report.docx" in file_names
        assert ".hidden_credentials" in file_names

        # Verify SHA-256 generated for all 3 files
        for s in scans_data:
            assert s["sha256"] is not None
            assert len(s["sha256"]) == 64

        # Verify filter by hidden files
        hidden_resp = test_client.get(f"/api/v1/usb/scans?usb_event_id={event_id}&is_hidden=true")
        assert hidden_resp.status_code == 200
        hidden_scans = hidden_resp.json()
        assert len(hidden_scans) == 1
        assert hidden_scans[0]["file_name"] == ".hidden_credentials"
