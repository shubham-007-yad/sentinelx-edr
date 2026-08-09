import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List


class TelemetryEnvelope:
    """
    Agent-side Standardized Telemetry Event Wrapper.
    Standardizes telemetry generated across USB, File Integrity, Process, Network, and Security Event collectors.
    """

    @staticmethod
    def wrap_event(
        category: str,
        event_type: str,
        source: str,
        device_id: str,
        payload: Dict[str, Any],
        host_info: Dict[str, Any] = None,
        correlation_id: str = None,
        tenant_id: str = "default_tenant"
    ) -> Dict[str, Any]:
        """
        Wraps collector payload into the unified BaseTelemetryEvent format with incident correlation tracking.
        """
        return {
            "event_id": str(uuid.uuid4()),
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category,
            "event_type": event_type,
            "source": source,
            "correlation_id": correlation_id or str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "schema_version": "1.0",
            "host_info": host_info or {},

            "payload": payload
        }

