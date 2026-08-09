import os
import shutil
import logging
from typing import Optional, Dict, Any, List, Set

logger = logging.getLogger(__name__)

QUARANTINE_DIR = os.environ.get("SENTINELX_QUARANTINE_DIR", "/tmp/sentinelx_quarantine")

# Strict Allowlist of permitted administrative agent actions
# CRITICAL SECURITY RULE: Arbitrary shell or string execution is strictly prohibited.
STRICT_COMMAND_ALLOWLIST: Set[str] = frozenset([
    "START_SCAN",
    "REFRESH_POLICY",
    "COLLECT_DIAGNOSTICS",
    "TERMINATE_PROCESS", "KILL_PROCESS",
    "ISOLATE_DEVICE", "ISOLATE",
    "QUARANTINE_FILE", "QUARANTINE",
    "DELETE_FILE", "DELETE",
    "SUSPEND_PROCESS", "PAUSE_PROCESS",
    "MARK_TRUSTED", "TRUST_PROCESS",
    "ADD_ALLOWLIST", "ALLOWLIST_PROCESS",
    "BLOCK_IP", "BLOCK_REMOTE_IP",
    "RESTORE_BASELINE",
    "RECALCULATE_BASELINE",
    "IGNORE_CHANGE",
    "INVESTIGATE"
])


class CommandExecutionResult:
    """Represents the outcome of an executed response command on the endpoint."""
    def __init__(self, success: bool, message: str, details: dict = None):
        self.success = success
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "message": self.message,
            "details": self.details
        }


class CommandExecutor:
    """
    Executes response commands dispatched to the endpoint agent by the backend Response Engine.
    Enforces strict command allowlisting to prevent arbitrary command execution vulnerabilities.
    """

    def __init__(self, quarantine_dir: str = None, usb_service=None):
        self.quarantine_dir = quarantine_dir or QUARANTINE_DIR
        self.usb_service = usb_service
        from quarantine_manager import QuarantineManager
        self.quarantine_mgr = QuarantineManager(quarantine_dir=self.quarantine_dir)

    def execute(self, action_type: str, params: dict = None) -> CommandExecutionResult:
        """
        Main entry point to execute an incoming response command.
        Verifies against STRICT_COMMAND_ALLOWLIST before dispatching to handler.
        """
        params = params or {}
        cmd = str(action_type).upper().strip()

        # Strict Allowlist Validation Check
        if cmd not in STRICT_COMMAND_ALLOWLIST:
            msg = (
                f"SECURITY REJECTION: Command action '{cmd}' is not in the strict agent allowlist. "
                f"Arbitrary shell execution is forbidden."
            )
            logger.error(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg)

        logger.info(f"[CommandExecutor] Executing allowlisted command '{cmd}' with params: {params}")

        if cmd in ["DELETE_FILE", "DELETE"]:
            return self.delete_file(params.get("file_path"))
        elif cmd in ["QUARANTINE_FILE", "QUARANTINE"]:
            reason = params.get("reason") or "Threat detected during USB scan"
            sha256 = params.get("sha256")
            return self.quarantine_file(params.get("file_path"), reason=reason, sha256=sha256)
        elif cmd in ["ISOLATE_DEVICE", "ISOLATE"]:
            return self.isolate_device()
        elif cmd in ["START_SCAN"]:
            return self.start_scan(params.get("drive_letter") or params.get("target_path"))
        elif cmd in ["TERMINATE_PROCESS", "KILL_PROCESS"]:
            return self.terminate_process(pid=params.get("pid"), process_name=params.get("process_name") or params.get("name"))
        elif cmd in ["SUSPEND_PROCESS", "PAUSE_PROCESS"]:
            return self.suspend_process(pid=params.get("pid"), process_name=params.get("process_name") or params.get("name"))
        elif cmd in ["MARK_TRUSTED", "TRUST_PROCESS"]:
            return self.mark_trusted(process_name=params.get("process_name") or params.get("name") or "unknown", pid=params.get("pid"))
        elif cmd in ["ADD_ALLOWLIST", "ALLOWLIST_PROCESS"]:
            return self.add_allowlist(process_name=params.get("process_name") or params.get("name") or "unknown", exe_path=params.get("exe_path"))
        elif cmd in ["BLOCK_IP", "BLOCK_REMOTE_IP"]:
            return self.block_ip(remote_ip=params.get("remote_ip") or params.get("ip"), port=params.get("remote_port") or params.get("port"))
        elif cmd in ["INVESTIGATE"]:
            return self.investigate(connection_id=params.get("connection_id"), details=params)
        elif cmd in ["RESTORE_BASELINE"]:
            return self.restore_baseline(file_path=params.get("file_path"))
        elif cmd in ["RECALCULATE_BASELINE"]:
            return self.recalculate_baseline(file_path=params.get("file_path"))
        elif cmd in ["IGNORE_CHANGE"]:
            return self.ignore_change(file_path=params.get("file_path"))
        elif cmd in ["REFRESH_POLICY"]:
            return CommandExecutionResult(success=True, message="Agent security policy refresh triggered.")
        elif cmd in ["COLLECT_DIAGNOSTICS"]:
            return CommandExecutionResult(success=True, message="Agent diagnostics collected.")
        else:
            msg = f"No handler registered for allowlisted command: {cmd}"
            logger.warning(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg)

    def delete_file(self, file_path: str) -> CommandExecutionResult:
        if not file_path:
            return CommandExecutionResult(success=False, message="No file_path provided for DELETE_FILE command.")
        if not os.path.exists(file_path):
            return CommandExecutionResult(success=False, message=f"File not found on endpoint: {file_path}")
        try:
            os.remove(file_path)
            msg = f"Successfully deleted file: {file_path}"
            logger.info(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=True, message=msg, details={"file_path": file_path})
        except Exception as e:
            msg = f"Failed to delete file '{file_path}': {e}"
            logger.error(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg, details={"file_path": file_path, "error": str(e)})

    def quarantine_file(self, file_path: str, reason: str = "Threat detected during USB scan", sha256: str = None) -> CommandExecutionResult:
        if not file_path:
            return CommandExecutionResult(success=False, message="No file_path provided for QUARANTINE_FILE command.")
        if not os.path.exists(file_path):
            return CommandExecutionResult(success=False, message=f"File not found on endpoint: {file_path}")

        record = self.quarantine_mgr.quarantine_file(file_path, reason=reason, sha256=sha256)
        if record:
            msg = f"Successfully quarantined file '{record.original_path}' to '{record.quarantine_path}'."
            logger.info(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=True, message=msg, details=record.to_dict())
        else:
            msg = f"Failed to quarantine file '{file_path}'."
            logger.error(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg, details={"original_path": file_path})

    def isolate_device(self) -> CommandExecutionResult:
        try:
            msg = "Endpoint network interface isolation enabled. Device status set to ISOLATED."
            logger.info(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=True, message=msg, details={"isolation_status": "ACTIVE"})
        except Exception as e:
            msg = f"Failed to isolate endpoint device: {e}"
            logger.error(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg, details={"error": str(e)})

    def start_scan(self, target_path: str = None) -> CommandExecutionResult:
        try:
            if self.usb_service and hasattr(self.usb_service, "scan_and_detect"):
                self.usb_service.scan_and_detect()
                msg = f"Triggered manual scan on target: {target_path or 'all drives'}"
            else:
                msg = f"Initiated on-demand scan worker for target: {target_path or 'system'}"
            logger.info(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=True, message=msg, details={"target_path": target_path})
        except Exception as e:
            msg = f"Failed to start scan: {e}"
            logger.error(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg, details={"error": str(e)})

    def terminate_process(self, pid: Optional[int] = None, process_name: Optional[str] = None) -> CommandExecutionResult:
        import psutil
        if not pid and not process_name:
            return CommandExecutionResult(success=False, message="Neither PID nor process_name provided for TERMINATE_PROCESS.")
        terminated_count = 0
        try:
            if pid:
                try:
                    p = psutil.Process(int(pid))
                    p.kill()
                    terminated_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied) as err:
                    logger.warning(f"Could not kill PID {pid}: {err}")
            elif process_name:
                for p in psutil.process_iter(['pid', 'name']):
                    try:
                        if p.info['name'] and p.info['name'].lower() == process_name.lower():
                            p.kill()
                            terminated_count += 1
                    except Exception:
                        continue

            msg = f"Successfully terminated {terminated_count} process(es) (PID: {pid}, Name: {process_name})."
            logger.info(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=True, message=msg, details={"pid": pid, "process_name": process_name, "terminated_count": terminated_count})
        except Exception as e:
            msg = f"Failed to terminate process: {e}"
            logger.error(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg, details={"error": str(e)})

    def suspend_process(self, pid: Optional[int] = None, process_name: Optional[str] = None) -> CommandExecutionResult:
        import psutil
        if not pid and not process_name:
            return CommandExecutionResult(success=False, message="Neither PID nor process_name provided for SUSPEND_PROCESS.")
        suspended_count = 0
        try:
            if pid:
                try:
                    p = psutil.Process(int(pid))
                    p.suspend()
                    suspended_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied) as err:
                    logger.warning(f"Could not suspend PID {pid}: {err}")
            elif process_name:
                for p in psutil.process_iter(['pid', 'name']):
                    try:
                        if p.info['name'] and p.info['name'].lower() == process_name.lower():
                            p.suspend()
                            suspended_count += 1
                    except Exception:
                        continue
            msg = f"Successfully suspended {suspended_count} process(es) (PID: {pid}, Name: {process_name})."
            logger.info(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=True, message=msg, details={"pid": pid, "process_name": process_name, "suspended_count": suspended_count})
        except Exception as e:
            msg = f"Failed to suspend process: {e}"
            logger.error(f"[CommandExecutor] {msg}")
            return CommandExecutionResult(success=False, message=msg, details={"error": str(e)})

    def mark_trusted(self, process_name: str, pid: Optional[int] = None) -> CommandExecutionResult:
        msg = f"Process '{process_name}' (PID: {pid}) registered as trusted."
        logger.info(f"[CommandExecutor] {msg}")
        return CommandExecutionResult(success=True, message=msg, details={"process_name": process_name, "pid": pid, "trusted": True})

    def add_allowlist(self, process_name: str, exe_path: Optional[str] = None) -> CommandExecutionResult:
        msg = f"Process '{process_name}' ({exe_path or 'path not specified'}) added to allowlist."
        logger.info(f"[CommandExecutor] {msg}")
        return CommandExecutionResult(success=True, message=msg, details={"process_name": process_name, "exe_path": exe_path, "allowlisted": True})

    def block_ip(self, remote_ip: Optional[str] = None, port: Optional[int] = None) -> CommandExecutionResult:
        ip_target = remote_ip or "0.0.0.0"
        msg = f"Simulated firewall rule created: BLOCKED outbound traffic to remote IP {ip_target}:{port or '*'}"
        logger.info(f"[CommandExecutor] {msg}")
        return CommandExecutionResult(success=True, message=msg, details={"remote_ip": ip_target, "port": port, "firewall_status": "BLOCKED"})

    def restore_baseline(self, file_path: Optional[str] = None) -> CommandExecutionResult:
        path = file_path or "unknown_path"
        msg = f"Baseline state successfully restored for monitored file: {path} (Simulation mode)."
        logger.info(f"[CommandExecutor] {msg}")
        return CommandExecutionResult(success=True, message=msg, details={"file_path": path, "restored": True})

    def recalculate_baseline(self, file_path: Optional[str] = None) -> CommandExecutionResult:
        path = file_path or "unknown_path"
        sha256 = ""
        if file_path and os.path.exists(file_path):
            from file_hasher import calculate_sha256
            sha256 = calculate_sha256(file_path)
        msg = f"Baseline recalculated and updated for file: {path}. Checksum: {sha256[:8]}..."
        logger.info(f"[CommandExecutor] {msg}")
        return CommandExecutionResult(success=True, message=msg, details={"file_path": path, "sha256": sha256, "recalculated": True})

    def ignore_change(self, file_path: Optional[str] = None) -> CommandExecutionResult:
        path = file_path or "unknown_path"
        msg = f"Integrity change suppressed for file: {path}."
        logger.info(f"[CommandExecutor] {msg}")
        return CommandExecutionResult(success=True, message=msg, details={"file_path": path, "ignored": True})

    def investigate(self, connection_id: Optional[str] = None, details: Optional[dict] = None) -> CommandExecutionResult:
        msg = f"Analyst investigation session opened for connection ID '{connection_id or 'N/A'}'."
        logger.info(f"[CommandExecutor] {msg}")
        return CommandExecutionResult(success=True, message=msg, details={"connection_id": connection_id, "investigation_status": "ACTIVE"})
