import json
import logging
import re
import sys
import uuid
from datetime import datetime, timezone
from app.core.config import settings

class SensitiveDataFilter(logging.Filter):
    """
    Sanitizes log records to prevent accidental leaks of sensitive tokens, passwords,
    API keys, and connection strings containing credentials in logs.
    """
    SENSITIVE_PATTERNS = [
        (re.compile(r'(password|passwd|secret|access_token|refresh_token|auth_token|api_key|private_key)\s*=\s*["\']?[^"\']+\s*["\']?', re.IGNORECASE), r'\1=***REDACTED***'),
        (re.compile(r'postgres(ql)?://([^:]+):([^@]+)@', re.IGNORECASE), r'postgresql://\2:***REDACTED***@'),
        (re.compile(r'redis://:([^@]+)@', re.IGNORECASE), r'redis://:***REDACTED***@'),
        (re.compile(r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', re.IGNORECASE), r'Bearer ***REDACTED***'),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern, repl in self.SENSITIVE_PATTERNS:
                msg = pattern.sub(repl, msg)
            record.msg = msg
        return True


class JSONLogFormatter(logging.Formatter):
    """
    Formats log records as standardized, structured JSON lines.
    Output Schema:
    {
      "timestamp": "ISO-8601",
      "level": "INFO|WARNING|ERROR",
      "service": "sentinelx-backend",
      "event": "EVENT_NAME",
      "event_id": "UUID",
      "correlation_id": "UUID|None",
      "device_id": "UUID|None",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "message": "Sanitized log message"
    }
    """

    def format(self, record: logging.LogRecord) -> str:
        now_iso = datetime.now(timezone.utc).isoformat()

        event_name = getattr(record, "event", getattr(record, "event_name", record.name.upper()))
        event_id = getattr(record, "event_id", str(uuid.uuid4()))
        correlation_id = getattr(record, "correlation_id", None)
        device_id = getattr(record, "device_id", None)
        service_name = getattr(record, "service", getattr(settings, "PROJECT_NAME", "sentinelx-backend"))
        severity = getattr(record, "severity", record.levelname)

        log_dict = {
            "timestamp": now_iso,
            "level": record.levelname,
            "service": service_name,
            "event": event_name,
            "event_id": event_id,
            "correlation_id": str(correlation_id) if correlation_id else None,
            "device_id": str(device_id) if device_id else None,
            "severity": severity,
            "message": record.getMessage()
        }

        if record.exc_info:
            log_dict["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_dict)


def setup_logging():
    log_level_str = getattr(settings, "LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(JSONLogFormatter())
    stream_handler.addFilter(SensitiveDataFilter())

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = [stream_handler]

logger = logging.getLogger("sentinelx")
setup_logging()

def log_event(
    logger_inst: logging.Logger,
    level: int,
    event: str,
    message: str,
    device_id: str = None,
    correlation_id: str = None,
    severity: str = None,
    service: str = None
):
    extra = {
        "event": event,
        "event_id": str(uuid.uuid4()),
        "device_id": device_id,
        "correlation_id": correlation_id,
        "severity": severity or logging.getLevelName(level),
        "service": service or getattr(settings, "PROJECT_NAME", "sentinelx-backend")
    }
    logger_inst.log(level, message, extra=extra)
