import hmac
import hashlib
from datetime import datetime, timezone
from command_channel import AgentCommandChannel
from config import config


def test_command_signature_valid_and_invalid():
    channel = AgentCommandChannel()
    ts = datetime.now(timezone.utc).isoformat()
    action_id = "test-action-123"
    action_type = "REFRESH_POLICY"
    device_id = "device-456"

    secret = getattr(config, "COMMAND_SIGNING_SECRET", None) or getattr(config, "JWT_SECRET", "sentinelx-edr-super-secret-key-2026-production-ready")

    # 1. Valid Signature
    msg_bytes = f"{action_id}:{action_type}:{ts}:{device_id}".encode("utf-8")
    valid_sig = hmac.new(secret.encode("utf-8"), msg_bytes, hashlib.sha256).hexdigest()

    valid_payload = {
        "event": "RESPONSE_COMMAND",
        "data": {
            "action_id": action_id,
            "action_type": action_type,
            "device_id": device_id,
            "timestamp": ts,
            "signature": valid_sig
        }
    }

    res = channel.process_incoming_command(valid_payload)
    assert res.success is True

    # 2. Tampered / Forged Signature
    forged_payload = {
        "event": "RESPONSE_COMMAND",
        "data": {
            "action_id": "test-action-999",
            "action_type": "ISOLATE_DEVICE",
            "device_id": device_id,
            "timestamp": ts,
            "signature": "bad_signature_string_xxxx"
        }
    }

    res_forged = channel.process_incoming_command(forged_payload)
    assert res_forged.success is False
    assert "FORGED COMMAND REJECTED" in res_forged.message
