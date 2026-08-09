import uuid
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.detection.behavior.aggregator import ProcessFileAggregator
from app.detection.behavior.metrics import (
    BehavioralMetrics,
    calculate_shannon_entropy,
    KNOWN_RANSOMWARE_EXTENSIONS,
    RANSOM_NOTE_PATTERNS
)

SHADOW_COPY_TAMPER_PATTERNS = [
    "vssadmin delete shadows",
    "vssadmin.exe delete shadows",
    "wbadmin delete catalog",
    "wbadmin.exe delete catalog",
    "bcdedit /set recoveryenabled no",
    "bcdedit.exe /set recoveryenabled no",
    "wmic shadowcopy delete",
    "powershell win32_shadowcopy"
]


@dataclass
class ProcessBehaviorSession:
    """
    State container for an active process behavior session.
    Monitors process lineage, event stream, real-time behavioral metrics, and windowed file activity.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str = "default_device"
    pid: Optional[int] = None
    process_name: str = "unknown.exe"
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_event_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    events_sequence: List[Dict[str, Any]] = field(default_factory=list)
    metrics: BehavioralMetrics = field(default_factory=BehavioralMetrics)
    aggregator: ProcessFileAggregator = field(default_factory=lambda: ProcessFileAggregator(pid=None))
    status: str = "ACTIVE"  # ACTIVE, SUSPICIOUS, MALICIOUS_RANSOMWARE, EXPIRED, CONTAINED
    affected_files: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.aggregator.pid is None and self.pid is not None:
            self.aggregator.pid = self.pid
            self.aggregator.process_name = self.process_name

    def add_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Appends an event to the session sequence and updates behavioral metrics.
        Supported event types:
        - FILE_CREATED, FILE_MODIFIED, FILE_DELETED, FILE_RENAMED
        - PROCESS_SPAWN, PROCESS_COMMAND
        - NETWORK_CONNECT
        """
        now = datetime.now(timezone.utc)
        self.last_event_time = now
        
        event_entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "event_type": event.get("event_type", "UNKNOWN"),
            "raw": event
        }

        event_type = event.get("event_type", "").upper()
        file_path = event.get("file_path") or event.get("path") or ""
        cmd_line = event.get("command_line") or event.get("cmd") or self.command_line or ""
        
        # Check command line for shadow copy tampering
        if cmd_line and not self.metrics.shadow_copy_deleted:
            cmd_lower = cmd_line.lower()
            if any(pattern in cmd_lower for pattern in SHADOW_COPY_TAMPER_PATTERNS):
                self.metrics.shadow_copy_deleted = True
                event_entry["flagged_reason"] = "SHADOW_COPY_DESTRUCTION"

        # File-level behavioral tracking
        if event_type in ["FILE_CREATED", "FILE_WRITE", "CREATE"]:
            self.metrics.file_created_count += 1
            self.aggregator.record_change(change_type="CREATED", path=file_path)
            self._analyze_file_attributes(file_path, event, event_entry)
            
        elif event_type in ["FILE_MODIFIED", "FILE_UPDATE", "MODIFY"]:
            self.metrics.file_modified_count += 1
            self.aggregator.record_change(
                change_type="MODIFIED",
                path=file_path,
                old_hash=event.get("old_hash"),
                new_hash=event.get("new_hash") or event.get("file_hash"),
                entropy=event_entry.get("entropy")
            )
            self._analyze_file_attributes(file_path, event, event_entry)

        elif event_type in ["FILE_DELETED", "FILE_REMOVE", "DELETE"]:
            self.metrics.file_deleted_count += 1
            self.aggregator.record_change(change_type="DELETED", path=file_path)
            if file_path:
                self.affected_files.append({"path": file_path, "action": "DELETED"})

        elif event_type in ["FILE_RENAMED", "FILE_MOVE", "RENAME"]:
            self.metrics.file_renamed_count += 1
            old_path = event.get("old_path", "")
            new_path = event.get("new_path") or file_path
            
            self.aggregator.record_change(
                change_type="RENAMED",
                path=file_path,
                old_path=old_path,
                new_path=new_path
            )
            
            # Check for ransomware extension appending
            if new_path:
                ext = os.path.splitext(new_path)[1].lower()
                if ext in KNOWN_RANSOMWARE_EXTENSIONS:
                    self.metrics.known_ransomware_ext_count += 1
                    event_entry["flagged_reason"] = f"KNOWN_RANSOMWARE_EXTENSION ({ext})"
            
            self.affected_files.append({"old_path": old_path, "new_path": new_path, "action": "RENAMED"})
            self._analyze_file_attributes(new_path, event, event_entry)

        elif event_type in ["NETWORK_CONNECT", "SOCKET_OUTBOUND"]:
            self.metrics.network_connection_count += 1

        # Calculate duration
        duration = (self.last_event_time - self.start_time).total_seconds()
        self.metrics.window_duration_seconds = max(1.0, duration)

        self.events_sequence.append(event_entry)
        
        # Update session status based on risk score
        score = self.metrics.calculate_composite_risk_score()
        if score >= 75.0:
            self.status = "MALICIOUS_RANSOMWARE"
        elif score >= 40.0:
            self.status = "SUSPICIOUS"

        return event_entry

    def _analyze_file_attributes(self, file_path: str, raw_event: Dict[str, Any], event_entry: Dict[str, Any]):
        """Inspects file payload entropy and checks for ransom note patterns."""
        if not file_path:
            return

        file_name = os.path.basename(file_path).lower()

        # 1. Ransom Note Check
        if any(pattern in file_name for pattern in RANSOM_NOTE_PATTERNS):
            self.metrics.ransom_note_count += 1
            event_entry["flagged_reason"] = f"RANSOM_NOTE_DROP ({file_name})"

        # 2. Entropy Evaluation
        entropy = raw_event.get("entropy")
        raw_bytes = raw_event.get("raw_bytes")
        
        if entropy is None and raw_bytes is not None:
            if isinstance(raw_bytes, str):
                raw_bytes = raw_bytes.encode("utf-8")
            entropy = calculate_shannon_entropy(raw_bytes)
        
        # If file exists locally on disk, calculate on actual bytes if available
        if entropy is None and os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    sample_data = f.read(65536)  # Read up to 64KB sample
                    entropy = calculate_shannon_entropy(sample_data)
            except Exception:
                pass

        if entropy is not None:
            self.metrics.record_entropy(entropy)
            event_entry["entropy"] = entropy
            self.affected_files.append({"path": file_path, "entropy": entropy, "action": "MODIFIED"})

    def prune_events_older_than(self, window_seconds: float = 60.0):
        """Trims events and metrics outside the sliding time window."""
        now = datetime.now(timezone.utc)
        cutoff_ts = now.timestamp() - window_seconds
        
        valid_events = []
        for ev in self.events_sequence:
            try:
                ev_dt = datetime.fromisoformat(ev["timestamp"])
                if ev_dt.timestamp() >= cutoff_ts:
                    valid_events.append(ev)
            except Exception:
                valid_events.append(ev)
        
        self.events_sequence = valid_events
        self.aggregator.prune_window(window_seconds)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "device_id": self.device_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "executable_path": self.executable_path,
            "command_line": self.command_line,
            "parent_pid": self.parent_pid,
            "start_time": self.start_time.isoformat(),
            "last_event_time": self.last_event_time.isoformat(),
            "event_count": len(self.events_sequence),
            "status": self.status,
            "metrics": self.metrics.to_dict(),
            "file_activity_summary": self.aggregator.get_summary(window_seconds=30.0),
            "affected_files_count": len(self.affected_files),
            "sample_affected_files": self.affected_files[-10:]
        }
