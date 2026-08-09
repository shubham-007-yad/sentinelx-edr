from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


@dataclass
class TimelineNode:
    """
    Individual chronological step in a behavioral attack timeline.
    """
    step_number: int
    timestamp: str
    event_type: str        # e.g., PROCESS_SPAWN, SHADOW_COPY_TAMPER, FILE_MODIFY, HIGH_ENTROPY_WRITE, RANSOM_NOTE_DROP, AUTO_ISOLATE
    title: str
    description: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    risk_delta: float      # Contribution to cumulative risk score
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "risk_delta": self.risk_delta,
            "metadata": self.metadata
        }


class BehaviorTimeline:
    """
    Chronological attack storyline builder.
    Constructs an interactive step-by-step forensic timeline from process behavior sessions.
    """
    def __init__(self, session_id: str, pid: Optional[int] = None, process_name: str = "unknown.exe"):
        self.session_id = session_id
        self.pid = pid
        self.process_name = process_name
        self.nodes: List[TimelineNode] = []
        self._current_step = 0
        self._cumulative_risk = 0.0

    def add_step(
        self,
        event_type: str,
        title: str,
        description: str,
        severity: str = "LOW",
        risk_delta: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None
    ) -> TimelineNode:
        """Appends a new chronological step node to the timeline."""
        self._current_step += 1
        self._cumulative_risk += risk_delta
        
        node = TimelineNode(
            step_number=self._current_step,
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            title=title,
            description=description,
            severity=severity,
            risk_delta=risk_delta,
            metadata=metadata or {}
        )
        self.nodes.append(node)
        return node

    def build_from_session_events(self, events: List[Dict[str, Any]]) -> List[TimelineNode]:
        """Generates timeline nodes directly from session raw events."""
        self.nodes.clear()
        self._current_step = 0
        self._cumulative_risk = 0.0

        for ev in events:
            ev_type = ev.get("event_type", "EVENT")
            raw = ev.get("raw", {})
            ts = ev.get("timestamp", datetime.now(timezone.utc).isoformat())
            flagged = ev.get("flagged_reason")
            entropy = ev.get("entropy")
            
            title = f"{ev_type}: {self.process_name} (PID {self.pid})"
            desc = f"Observed event {ev_type}"
            sev = "LOW"
            delta = 0.0

            if flagged and "SHADOW_COPY" in flagged:
                title = "🚨 Defense Evasion: Shadow Copy Deletion"
                desc = f"Process {self.process_name} executed shadow copy deletion command: {raw.get('command_line') or raw.get('cmd')}"
                sev = "CRITICAL"
                delta = 25.0

            elif flagged and "RANSOM_NOTE" in flagged:
                title = "📝 Ransom Note Created"
                desc = f"Ransom note created: {raw.get('file_path') or raw.get('path')}"
                sev = "HIGH"
                delta = 20.0

            elif entropy and entropy >= 7.5:
                title = "🔒 High Entropy File Modification"
                desc = f"File {raw.get('file_path') or raw.get('path')} written with encrypted payload (Entropy: {entropy})"
                sev = "HIGH"
                delta = 15.0

            elif ev_type in ["FILE_RENAMED", "RENAME"]:
                title = "🏷️ File Extension Renamed"
                desc = f"Renamed {raw.get('old_path')} -> {raw.get('new_path')}"
                sev = "MEDIUM"
                delta = 8.0

            self.add_step(
                event_type=ev_type,
                title=title,
                description=desc,
                severity=sev,
                risk_delta=delta,
                metadata={"raw_event": raw, "entropy": entropy, "flagged": flagged},
                timestamp=ts
            )

        return self.nodes

    def export_storyline(self) -> Dict[str, Any]:
        """Returns the full chronological attack storyline for UI visualization."""
        return {
            "session_id": self.session_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "total_steps": len(self.nodes),
            "cumulative_risk_score": round(self._cumulative_risk, 2),
            "timeline": [n.to_dict() for n in self.nodes]
        }
