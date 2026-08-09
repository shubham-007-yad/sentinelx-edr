import time
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set, Any, Optional
from datetime import datetime, timezone


@dataclass
class FileChangeRecord:
    """
    Granular record of a single file change event associated with a process.
    """
    path: str
    change_type: str         # CREATED, MODIFIED, DELETED, RENAMED
    timestamp: float         # epoch seconds
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    old_ext: Optional[str] = None
    new_ext: Optional[str] = None
    entropy: Optional[float] = None
    size_bytes: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "change_type": self.change_type,
            "timestamp": datetime.fromtimestamp(self.timestamp, timezone.utc).isoformat(),
            "old_path": self.old_path,
            "new_path": self.new_path,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "old_ext": self.old_ext,
            "new_ext": self.new_ext,
            "entropy": self.entropy,
            "size_bytes": self.size_bytes
        }


class ProcessFileAggregator:
    """
    Process-Level File Activity Aggregator.
    Tracks and aggregates filesystem actions per process within rolling time windows:
    - Files created / modified / deleted / renamed
    - Extension mutations (e.g. .docx -> .docx.locked)
    - SHA-256 hash modifications
    - Mutation velocity (e.g. 500 files modified in 30s)
    """

    def __init__(self, pid: Optional[int], process_name: str = "unknown.exe", default_window_seconds: float = 30.0):
        self.pid = pid
        self.process_name = process_name
        self.default_window_seconds = default_window_seconds
        
        self.records: List[FileChangeRecord] = []
        
        # Aggregated sets & maps
        self.created_files: Set[str] = set()
        self.modified_files: Set[str] = set()
        self.deleted_files: Set[str] = set()
        self.renamed_files: List[Dict[str, str]] = []  # [{"old": ..., "new": ...}]
        
        self.extension_changes: Dict[str, int] = {}    # "docx->locked": count
        self.sha_changes: List[Dict[str, Any]] = []    # [{"path": ..., "old_hash": ..., "new_hash": ...}]

    def record_change(
        self,
        change_type: str,
        path: str,
        old_path: Optional[str] = None,
        new_path: Optional[str] = None,
        old_hash: Optional[str] = None,
        new_hash: Optional[str] = None,
        entropy: Optional[float] = None,
        size_bytes: Optional[int] = None,
        timestamp: Optional[float] = None
    ) -> FileChangeRecord:
        """Records a new file activity event for this process."""
        ts = timestamp or time.time()
        
        old_ext = os.path.splitext(old_path or path)[1].lower() if (old_path or path) else ""
        new_ext = os.path.splitext(new_path or path)[1].lower() if (new_path or path) else ""
        
        rec = FileChangeRecord(
            path=path,
            change_type=change_type.upper(),
            timestamp=ts,
            old_path=old_path,
            new_path=new_path,
            old_hash=old_hash,
            new_hash=new_hash,
            old_ext=old_ext,
            new_ext=new_ext,
            entropy=entropy,
            size_bytes=size_bytes
        )
        self.records.append(rec)

        # Aggregate metrics
        ct = change_type.upper()
        if ct in ["CREATED", "CREATE"]:
            self.created_files.add(path)
            
        elif ct in ["MODIFIED", "MODIFY", "WRITE"]:
            self.modified_files.add(path)
            if old_hash and new_hash and old_hash != new_hash:
                self.sha_changes.append({
                    "path": path,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                    "timestamp": ts
                })

        elif ct in ["DELETED", "DELETE", "REMOVE"]:
            self.deleted_files.add(path)

        elif ct in ["RENAMED", "RENAME", "MOVE"]:
            target_old = old_path or path
            target_new = new_path or path
            self.renamed_files.append({"old_path": target_old, "new_path": target_new})
            
            if old_ext != new_ext and old_ext and new_ext:
                ext_key = f"{old_ext}->{new_ext}"
                self.extension_changes[ext_key] = self.extension_changes.get(ext_key, 0) + 1

        return rec

    def prune_window(self, window_seconds: Optional[float] = None):
        """Prunes records older than the specified time window."""
        win = window_seconds or self.default_window_seconds
        cutoff = time.time() - win
        
        self.records = [r for r in self.records if r.timestamp >= cutoff]
        
        # Re-build aggregated view for active window
        self.created_files = {r.path for r in self.records if r.change_type in ["CREATED", "CREATE"]}
        self.modified_files = {r.path for r in self.records if r.change_type in ["MODIFIED", "MODIFY", "WRITE"]}
        self.deleted_files = {r.path for r in self.records if r.change_type in ["DELETED", "DELETE", "REMOVE"]}
        
        self.renamed_files = [
            {"old_path": r.old_path or r.path, "new_path": r.new_path or r.path}
            for r in self.records if r.change_type in ["RENAMED", "RENAME", "MOVE"]
        ]
        
        self.sha_changes = [
            {"path": r.path, "old_hash": r.old_hash, "new_hash": r.new_hash, "timestamp": r.timestamp}
            for r in self.records if r.old_hash and r.new_hash and r.old_hash != r.new_hash
        ]

        self.extension_changes.clear()
        for r in self.records:
            if r.change_type in ["RENAMED", "RENAME", "MOVE"] and r.old_ext != r.new_ext and r.old_ext and r.new_ext:
                ext_key = f"{r.old_ext}->{r.new_ext}"
                self.extension_changes[ext_key] = self.extension_changes.get(ext_key, 0) + 1

    def get_summary(self, window_seconds: Optional[float] = None) -> Dict[str, Any]:
        """
        Returns aggregated summary of file activity for this process within the specified window.
        Example: 500 modified files in 30 seconds -> modification_rate = 16.67 files/sec.
        """
        win = window_seconds or self.default_window_seconds
        self.prune_window(win)
        
        total_mutations = len(self.records)
        modification_rate = round(len(self.modified_files) / max(1.0, win), 2)
        creation_rate = round(len(self.created_files) / max(1.0, win), 2)
        deletion_rate = round(len(self.deleted_files) / max(1.0, win), 2)
        rename_rate = round(len(self.renamed_files) / max(1.0, win), 2)

        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "window_seconds": win,
            "total_records_in_window": total_mutations,
            "counts": {
                "created": len(self.created_files),
                "modified": len(self.modified_files),
                "deleted": len(self.deleted_files),
                "renamed": len(self.renamed_files),
                "sha_changes": len(self.sha_changes),
                "extension_mutations": sum(self.extension_changes.values())
            },
            "rates_per_second": {
                "modification_rate": modification_rate,
                "creation_rate": creation_rate,
                "deletion_rate": deletion_rate,
                "rename_rate": rename_rate
            },
            "extension_changes": self.extension_changes,
            "sha_changes_count": len(self.sha_changes),
            "sample_sha_changes": self.sha_changes[-5:],
            "sample_renamed": self.renamed_files[-5:],
            "is_mass_modification_burst": len(self.modified_files) >= 50 or modification_rate >= 5.0
        }
