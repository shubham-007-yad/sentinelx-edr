from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from app.detection.behavior.session import ProcessBehaviorSession
from app.detection.behavior.timeline import BehaviorTimeline
from app.detection.behavior.correlation import BehaviorCorrelationRules, CorrelationMatch


class BehaviorCorrelationEngine:
    """
    Behavioral Correlation Engine for SentinelX EDR.
    Maintains process behavior sessions, runs multi-event sequence correlation rules,
    tracks forensic attack timelines, and evaluates ransomware threats across endpoints.
    """
    def __init__(self, observation_window_seconds: float = 60.0):
        self.observation_window_seconds = observation_window_seconds
        # Active sessions mapped by session_id
        self.sessions: Dict[str, ProcessBehaviorSession] = {}
        # Mapping from (device_id, pid) -> session_id
        self.pid_map: Dict[str, str] = {}
        # Timelines mapped by session_id
        self.timelines: Dict[str, BehaviorTimeline] = {}

    def get_or_create_session(
        self,
        device_id: str,
        pid: Optional[int],
        process_name: str = "unknown.exe",
        executable_path: Optional[str] = None,
        command_line: Optional[str] = None,
        parent_pid: Optional[int] = None
    ) -> ProcessBehaviorSession:
        """Retrieves an active session for (device_id, pid) or initializes a new session."""
        key = f"{device_id}:{pid}" if pid is not None else f"{device_id}:{process_name}"
        
        if key in self.pid_map:
            session_id = self.pid_map[key]
            if session_id in self.sessions:
                session = self.sessions[session_id]
                # Update attributes if provided
                if process_name and process_name != "unknown.exe":
                    session.process_name = process_name
                if executable_path:
                    session.executable_path = executable_path
                if command_line:
                    session.command_line = command_line
                return session

        # Create new session
        session = ProcessBehaviorSession(
            device_id=device_id,
            pid=pid,
            process_name=process_name or "unknown.exe",
            executable_path=executable_path,
            command_line=command_line,
            parent_pid=parent_pid
        )
        self.sessions[session.session_id] = session
        self.pid_map[key] = session.session_id
        self.timelines[session.session_id] = BehaviorTimeline(
            session_id=session.session_id,
            pid=pid,
            process_name=session.process_name
        )
        return session

    def ingest_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests a raw telemetry event into the Behavioral Correlation Engine.
        Process binding logic:
        1. Extract device_id, pid, process_name.
        2. Append event to process session.
        3. Run multi-event sequence correlation rules.
        4. Rebuild attack timeline.
        5. Return comprehensive evaluation result.
        """
        device_id = str(raw_event.get("device_id") or "default_device")
        pid = raw_event.get("pid") or raw_event.get("process_id")
        process_name = raw_event.get("process_name") or "unknown.exe"
        executable_path = raw_event.get("executable_path") or raw_event.get("process_path")
        command_line = raw_event.get("command_line") or raw_event.get("cmd")

        session = self.get_or_create_session(
            device_id=device_id,
            pid=pid,
            process_name=process_name,
            executable_path=executable_path,
            command_line=command_line
        )

        # 1. Add event to session
        ev_entry = session.add_event(raw_event)

        # 2. Evaluate multi-event correlation rules
        correlation_matches = BehaviorCorrelationRules.evaluate_all(session)

        # 3. Update timeline
        timeline = self.timelines.get(session.session_id)
        if timeline:
            timeline.build_from_session_events(session.events_sequence)

        # 4. Calculate Risk Score & Response recommendation
        risk_score = session.metrics.calculate_composite_risk_score()
        severity = session.metrics.severity

        should_terminate_process = False
        should_isolate_device = False
        
        if risk_score >= 75.0 or any(m.severity == "CRITICAL" for m in correlation_matches):
            should_terminate_process = True
            should_isolate_device = True

        return {
            "session_id": session.session_id,
            "device_id": device_id,
            "pid": pid,
            "process_name": session.process_name,
            "composite_risk_score": risk_score,
            "severity": severity,
            "status": session.status,
            "metrics": session.metrics.to_dict(),
            "correlation_matches": [m.to_dict() for m in correlation_matches],
            "recommendations": {
                "terminate_process": should_terminate_process,
                "isolate_device": should_isolate_device,
                "quarantine_files": len(session.affected_files) > 0
            },
            "ingested_event": ev_entry
        }

    def get_session_timeline(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Returns the forensic attack timeline for a session."""
        timeline = self.timelines.get(session_id)
        if timeline:
            return timeline.export_storyline()
        return None

    def list_active_sessions(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists active behavioral sessions."""
        results = []
        for s in self.sessions.values():
            if device_id and s.device_id != device_id:
                continue
            results.append(s.to_dict())
        return results

    def prune_inactive_sessions(self, max_idle_seconds: float = 300.0):
        """Cleans up expired or idle process behavior sessions."""
        now = datetime.now(timezone.utc).timestamp()
        expired_ids = []
        for s_id, s in self.sessions.items():
            idle = now - s.last_event_time.timestamp()
            if idle > max_idle_seconds:
                expired_ids.append(s_id)

        for s_id in expired_ids:
            s = self.sessions.pop(s_id, None)
            if s:
                key = f"{s.device_id}:{s.pid}" if s.pid is not None else f"{s.device_id}:{s.process_name}"
                self.pid_map.pop(key, None)
                self.timelines.pop(s_id, None)
