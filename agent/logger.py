import json
import logging
import re
import sys
import uuid
from datetime import datetime, timezone
from config import config

class AgentSensitiveDataFilter(logging.Filter):
    """
    Sanitizes agent log records to prevent accidental leaks of sensitive tokens, passwords,
    API keys, and file paths containing secrets in stdout/stderr logs.
    """
    SENSITIVE_PATTERNS = [
        (re.compile(r'(password|passwd|secret|access_token|refresh_token|auth_token|api_key|private_key)\s*=\s*["\']?[^"\']+\s*["\']?', re.IGNORECASE), r'\1=***REDACTED***'),
        (re.compile(r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', re.IGNORECASE), r'Bearer ***REDACTED***'),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern, repl in self.SENSITIVE_PATTERNS:
                msg = pattern.sub(repl, msg)
            record.msg = msg
        return True


class AgentJSONLogFormatter(logging.Formatter):
    """
    Formats agent log records as standardized, structured JSON lines.
    """
    def format(self, record: logging.LogRecord) -> str:
        now_iso = datetime.now(timezone.utc).isoformat()

        event_name = getattr(record, "event", getattr(record, "event_name", record.name.upper()))
        event_id = getattr(record, "event_id", str(uuid.uuid4()))
        correlation_id = getattr(record, "correlation_id", None)
        device_id = getattr(record, "device_id", None)
        severity = getattr(record, "severity", record.levelname)

        log_dict = {
            "timestamp": now_iso,
            "level": record.levelname,
            "service": "sentinelx-agent",
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


def setup_logger(name: str = "SentinelX-Agent") -> logging.Logger:
    """Configures and returns structured JSON logger for the SentinelX Agent."""
    logger_inst = logging.getLogger(name)
    
    if logger_inst.handlers:
        return logger_inst

    log_level = getattr(logging, config.LOG_LEVEL, logging.INFO)
    logger_inst.setLevel(log_level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(AgentJSONLogFormatter())
    console_handler.addFilter(AgentSensitiveDataFilter())

    logger_inst.addHandler(console_handler)
    return logger_inst


logger = setup_logger()
