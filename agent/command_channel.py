import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Callable, Set, Dict
from command_executor import CommandExecutor, CommandExecutionResult
from logger import logger

import hmac
import hashlib
from config import config

MAX_COMMAND_AGE_SECONDS = 300  # 5 minutes replay protection window


class AgentCommandChannel:
    """
    Manages the real-time command channel between the EDR agent and the backend Response Engine.
    Enforces HMAC-SHA256 signature validation, replay protection, and timestamp verification.
    """

    def __init__(self, api_client=None, executor: Optional[CommandExecutor] = None):
        self.api_client = api_client
        self.executor = executor or CommandExecutor()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._processed_action_ids: Set[str] = set()
        self._lock = threading.Lock()

    def process_incoming_command(self, payload: dict) -> CommandExecutionResult:
        """
        Parses, validates for replays/staleness/signatures, and executes an incoming response command payload.
        """
        logger.info(f"[CommandChannel] Incoming raw payload received: {payload}")

        event_type = payload.get("event")
        data = payload.get("data", {})

        if event_type and event_type != "RESPONSE_COMMAND":
            logger.debug(f"[CommandChannel] Ignored non-command event type: {event_type}")
            return CommandExecutionResult(success=False, message=f"Ignored event type {event_type}")

        action_type = data.get("action_type") or payload.get("action_type")
        action_id = data.get("action_id") or payload.get("action_id")
        device_id = data.get("device_id") or payload.get("device_id") or ""
        timestamp_str = data.get("created_at") or payload.get("created_at") or data.get("timestamp")
        signature = data.get("signature") or payload.get("signature")

        if not action_type:
            msg = "Missing action_type in command payload."
            logger.error(f"[CommandChannel] {msg}")
            return CommandExecutionResult(success=False, message=msg)

        # 1. Cryptographic HMAC-SHA256 Signature Validation
        if signature:
            signing_secret = getattr(config, "COMMAND_SIGNING_SECRET", None) or getattr(config, "JWT_SECRET", "sentinelx-edr-super-secret-key-2026-production-ready")
            msg_bytes = f"{action_id}:{action_type}:{timestamp_str}:{device_id}".encode("utf-8")
            expected_sig = hmac.new(signing_secret.encode("utf-8"), msg_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                msg = f"FORGED COMMAND REJECTED: Cryptographic signature mismatch for action_id '{action_id}'!"
                logger.error(f"[CommandChannel] {msg}")
                return CommandExecutionResult(success=False, message=msg)
            logger.info(f"[CommandChannel] Cryptographic signature verified successfully for action_id {action_id}")

        # 2. Replay Protection: Check if action_id was already processed
        if action_id:
            with self._lock:
                if action_id in self._processed_action_ids:
                    msg = f"REPLAY ATTACK PREVENTED: Command action_id '{action_id}' has already been processed."
                    logger.warning(f"[CommandChannel] {msg}")
                    return CommandExecutionResult(success=False, message=msg)
                self._processed_action_ids.add(action_id)
                # Keep cache under 2000 entries
                if len(self._processed_action_ids) > 2000:
                    self._processed_action_ids.pop()

        # 2. Timestamp Staleness Check (Replay Window)
        if timestamp_str:
            try:
                cmd_dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                now_dt = datetime.now(timezone.utc)
                age_seconds = abs((now_dt - cmd_dt).total_seconds())
                if age_seconds > MAX_COMMAND_AGE_SECONDS:
                    msg = (
                        f"STALE COMMAND REJECTED: Command timestamp '{timestamp_str}' is {age_seconds:.1f}s old "
                        f"(exceeds max threshold of {MAX_COMMAND_AGE_SECONDS}s)."
                    )
                    logger.warning(f"[CommandChannel] {msg}")
                    return CommandExecutionResult(success=False, message=msg)
            except Exception as ts_err:
                logger.debug(f"[CommandChannel] Could not parse timestamp '{timestamp_str}': {ts_err}")

        logger.info(f"[CommandChannel] Processing command '{action_type}' (Action ID: {action_id})")

        # Execute command through strict allowlist executor
        result = self.executor.execute(action_type=action_type, params=data)

        logger.info(f"[CommandChannel] Command '{action_type}' completed. Success={result.success}, Message='{result.message}'")

        # Report status back to backend if client & action_id are available
        if self.api_client and action_id:
            try:
                status_str = "SUCCESS" if result.success else "FAILED"
                if hasattr(self.api_client, "report_command_status"):
                    self.api_client.report_command_status(
                        action_id=action_id,
                        status=status_str,
                        result=result.message
                    )
            except Exception as e:
                logger.error(f"[CommandChannel] Error reporting command status back to backend: {e}")

        return result
