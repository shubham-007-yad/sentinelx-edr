import os
from telemetry_buffer import LocalTelemetryBuffer, flush_offline_telemetry


def test_telemetry_buffer_enqueue_and_flush(tmp_path):
    buffer_file = str(tmp_path / ".test_telemetry_buffer.json")
    buf = LocalTelemetryBuffer(buffer_file=buffer_file)

    # 1. Enqueue events offline
    buf.enqueue({"event_type": "PROCESS_START", "process": "malware.exe"})
    buf.enqueue({"event_type": "NETWORK_CONNECT", "ip": "1.2.3.4"})

    assert buf.count() == 2
    assert os.path.exists(buffer_file)

    # Verify 0600 file permissions
    stat = os.stat(buffer_file)
    assert oct(stat.st_mode)[-3:] in ("600", "700")

    # Mock APIClient for flush
    class DummyResponse:
        status_code = 201

    class DummySession:
        def post(self, url, json=None, timeout=None):
            return DummyResponse()

    class DummyAPIClient:
        backend_url = "http://localhost:8000/api/v1"
        device_id = "test-device-uuid"
        session = DummySession()

    # Flush offline items
    flushed = flush_offline_telemetry(DummyAPIClient(), buffer_instance=buf, batch_size=10)
    assert flushed == 2
    assert buf.count() == 0
