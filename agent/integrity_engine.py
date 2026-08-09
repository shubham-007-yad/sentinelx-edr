import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable
from logger import logger
from file_hasher import calculate_sha256


class BaselineRecord:

    def __init__(self, file_path: str, sha256: str, size: int, is_executable: bool, last_modified: str, owner: Optional[str] = None):
        self.file_path = file_path
        self.sha256 = sha256
        self.size = size
        self.is_executable = is_executable
        self.last_modified = last_modified
        self.owner = owner


DEFAULT_FIM_POLICY: Dict[str, Any] = {
    "protected_folders": ["Desktop", "Downloads", "Documents", "Startup"],
    "excluded_folders": [".git", "node_modules", "tmp", "Cache", "AppData/Local/Temp"],
    "hash_algorithm": "SHA-256",
    "ransomware_modification_threshold": 20,
    "ransomware_entropy_threshold": 7.2,
    "ignore_temporary_files": True,
    "auto_quarantine_ransomware": True
}

TEMP_EXTENSIONS = {".tmp", ".swp", ".bak"}


class AgentIntegrityEngine:
    """
    Day 11 — File Integrity Engine (Phase 3) with Dynamic FIM Security Policy Support.
    Maintains baseline records, computes SHA-256, file size, permissions, and diffs on file changes.
    Enforces excluded folders and temporary file filtering per active FIM Policy.
    """

    def __init__(
        self,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        policy: Optional[Dict[str, Any]] = None
    ):
        self.baseline: Dict[str, BaselineRecord] = {}
        self.event_callback = event_callback
        self.policy: Dict[str, Any] = dict(DEFAULT_FIM_POLICY)
        if policy:
            self.policy.update(policy)

    def update_policy(self, new_policy: Dict[str, Any]):
        """Dynamically updates active FIM & Ransomware Security Policy."""
        logger.info("[IntegrityEngine] Applying updated FIM security policy configuration.")
        self.policy.update(new_policy)

    def set_baseline(self, records: List[Dict[str, Any]]):
        """
        Populate or reset the local baseline records map.
        """
        self.baseline.clear()
        for r in records:
            path = os.path.abspath(r["file_path"])
            self.baseline[path] = BaselineRecord(
                file_path=path,
                sha256=r.get("sha256", ""),
                size=r.get("size", 0),
                is_executable=r.get("is_executable", False),
                last_modified=r.get("last_modified", ""),
                owner=r.get("owner")
            )
        logger.info(f"[IntegrityEngine] Local baseline initialized with {len(self.baseline)} records.")

    def should_ignore_file(self, file_path: str) -> bool:
        norm_path = file_path.replace("\\", "/").lower()
        excluded_folders = [f.lower() for f in self.policy.get("excluded_folders", [])]
        for exc in excluded_folders:
            if exc and exc in norm_path:
                return True

        if self.policy.get("ignore_temporary_files", True):
            fname = os.path.basename(file_path).lower()
            if fname.startswith("~$") or any(fname.endswith(ext) for ext in TEMP_EXTENSIONS):
                return True

        return False

    def process_file_event(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a real-time file event from FileWatcher, compare against baseline,
        compute new SHA-256 and size, and generate an Integrity Event.
        """
        event_type = event_payload.get("event_type", "MODIFIED")
        file_path = os.path.abspath(event_payload["file_path"])

        if self.should_ignore_file(file_path):
            logger.debug(f"[IntegrityEngine Policy] Ignoring file event for '{file_path}' per FIM exclusion rules.")
            return {
                "event_type": event_type,
                "file_path": file_path,
                "status": "IGNORED_BY_POLICY",
                "is_changed": False,
                "changes_detected": [],
                "details": f"File event ignored per FIM policy exclusion rules for path: {file_path}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        file_name = event_payload.get("file_name", os.path.basename(file_path))
        old_path = os.path.abspath(event_payload["old_path"]) if event_payload.get("old_path") else None

        current_hash = event_payload.get("sha256", "")
        current_size = event_payload.get("size", 0)
        is_exec = event_payload.get("is_executable", False)
        timestamp = event_payload.get("timestamp", datetime.now(timezone.utc).isoformat())

        # If hash not supplied, compute live
        if not current_hash and os.path.exists(file_path) and event_type != "DELETED":
            current_hash = calculate_sha256(file_path)
            try:
                current_size = os.path.getsize(file_path)
            except Exception:
                pass

        lookup_key = old_path if (event_type == "RENAMED" and old_path) else file_path
        baseline_record = self.baseline.get(lookup_key)

        changes = []
        status = "UNCHANGED"
        is_changed = False
        details = ""
        baseline_sha = baseline_record.sha256 if baseline_record else None
        baseline_sz = baseline_record.size if baseline_record else None

        if not baseline_record:
            if event_type == "DELETED":
                status = "DELETED"
                is_changed = True
                changes.append("untracked_file_deleted")
                details = f"Untracked file deleted: {file_path}"
            else:
                status = "NEW_FILE"
                is_changed = True
                changes.append("untracked_file_created")
                details = f"New untracked file generated in monitored folder: {file_path}"
                # Add to local baseline
                self.baseline[file_path] = BaselineRecord(
                    file_path=file_path,
                    sha256=current_hash,
                    size=current_size,
                    is_executable=is_exec,
                    last_modified=timestamp,
                    owner=event_payload.get("owner")
                )
        else:
            if event_type == "DELETED":
                status = "DELETED"
                is_changed = True
                changes.append("file_deleted")
                details = f"Monitored baseline file deleted: {file_path}"
                self.baseline.pop(lookup_key, None)
            else:
                if current_hash and baseline_record.sha256 != current_hash:
                    changes.append("sha256_mismatch")
                if current_size != baseline_record.size:
                    changes.append("size_mismatch")
                if is_exec != baseline_record.is_executable:
                    changes.append("executable_permission_changed")
                if event_type == "RENAMED" or (old_path and old_path != file_path):
                    changes.append("file_renamed_or_moved")

                if changes:
                    status = "CHANGED"
                    is_changed = True
                    diff_summary = ", ".join(changes)
                    details = f"File integrity change detected ({diff_summary}). Path: {file_path}"
                    # Update local baseline entry
                    if old_path and old_path in self.baseline:
                        self.baseline.pop(old_path, None)
                    self.baseline[file_path] = BaselineRecord(
                        file_path=file_path,
                        sha256=current_hash if current_hash else baseline_record.sha256,
                        size=current_size,
                        is_executable=is_exec,
                        last_modified=timestamp,
                        owner=event_payload.get("owner") or baseline_record.owner
                    )
                else:
                    status = "UNCHANGED"
                    is_changed = False
                    details = f"File event received; content matches baseline (SHA-256: {baseline_record.sha256[:8]}...)"

        integrity_event = {
            "event_type": event_type,
            "file_path": file_path,
            "file_name": file_name,
            "old_path": old_path,
            "status": status,
            "is_changed": is_changed,
            "changes_detected": changes,
            "baseline_sha256": baseline_sha,
            "current_sha256": current_hash,
            "baseline_size": baseline_sz,
            "current_size": current_size,
            "is_executable": is_exec,
            "details": details,
            "timestamp": timestamp
        }

        if is_changed and self.event_callback:
            try:
                self.event_callback(integrity_event)
            except Exception as e:
                logger.error(f"[IntegrityEngine] Error in event callback: {e}")

        return integrity_event
