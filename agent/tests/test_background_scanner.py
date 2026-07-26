import os
import tempfile
import pytest
from unittest.mock import MagicMock
from background_scanner import USBScanPipelineWorker


def test_background_scanner_pipeline_task_execution():
    mock_api = MagicMock()
    mock_api.send_usb_scans.return_value = [{"id": "scan-1"}, {"id": "scan-2"}]

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create sample files
        f1 = os.path.join(tmpdir, "test1.txt")
        f2 = os.path.join(tmpdir, "test2.exe")
        with open(f1, "w") as f:
            f.write("content 1")
        with open(f2, "wb") as f:
            f.write(b"content 2")

        worker = USBScanPipelineWorker(api_client=mock_api, batch_size=10)
        summary = worker.process_scan_task("usb-event-uuid-1234", tmpdir)

        assert summary["scanned_count"] == 2
        assert summary["uploaded_count"] == 2
        assert mock_api.send_usb_scans.called

        # Verify call arguments to send_usb_scans
        args, kwargs = mock_api.send_usb_scans.call_args
        scans_data = args[0]
        assert len(scans_data) == 2
        assert scans_data[0]["usb_event_id"] == "usb-event-uuid-1234"
        assert scans_data[0]["sha256"] is not None
        assert len(scans_data[0]["sha256"]) == 64


def test_background_scanner_queue():
    mock_api = MagicMock()
    mock_api.send_usb_scans.return_value = []

    with tempfile.TemporaryDirectory() as tmpdir:
        f1 = os.path.join(tmpdir, "data.bin")
        with open(f1, "wb") as f:
            f.write(b"data")

        worker = USBScanPipelineWorker(api_client=mock_api, batch_size=10)
        worker.start()

        worker.enqueue_scan("usb-event-uuid-5678", tmpdir)
        worker.scan_queue.join()

        worker.stop()
        assert mock_api.send_usb_scans.called
