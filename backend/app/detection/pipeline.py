import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.detection.event import DetectionEvent
from app.models.threat import Threat, ThreatType, ThreatSeverity
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.detection.scoring import threat_scorer
from app.core.websocket_manager import websocket_manager
from app.services import response_service

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """
    Unified Telemetry Detection Pipeline for SentinelX EDR:
    Receives standardized DetectionEvent objects from USB, Files, Processes, and Network subsystems.

    Flow:
    DetectionEvent ➔ Threat Scoring ➔ Alert Generation ➔ Response Engine ➔ Audit Logging ➔ WebSocket Broadcast
    """

    def process_event(self, db: Session, event: DetectionEvent) -> Dict[str, Any]:
        """
        Executes the shared 5-stage detection event processing pipeline.
        """
        logger.info(
            f"[DetectionPipeline] Processing {event.source_subsystem} DetectionEvent: "
            f"Rule='{event.rule_name}', Severity={event.severity}, Device={event.device_id}"
        )

        # ----------------------------------------------------
        # Stage 1: Threat Scoring & Persistence
        # ----------------------------------------------------
        try:
            severity_enum = ThreatSeverity(event.severity)
        except Exception:
            severity_enum = ThreatSeverity.HIGH

        try:
            threat_type_enum = ThreatType(event.threat_type)
        except Exception:
            threat_type_enum = ThreatType.ANOMALOUS_FILE

        try:
            threat = Threat(
                threat_type=threat_type_enum,
                severity=severity_enum,
                rule_name=event.rule_name,
                description=f"[{event.source_subsystem}] {event.description}"
            )
            db.add(threat)
            db.commit()
            db.refresh(threat)
        except Exception:
            db.rollback()
            threat = Threat(
                threat_type=ThreatType.SUSPICIOUS_PROCESS_BEHAVIOR,
                severity=severity_enum,
                rule_name=event.rule_name,
                description=f"[{event.source_subsystem}] {event.description}"
            )
            db.add(threat)
            db.commit()
            db.refresh(threat)


        # Calculate Threat Risk Score
        risk_score = threat_scorer.get_severity_score(threat.severity)

        # ----------------------------------------------------
        # Stage 2: Alert Generation
        # ----------------------------------------------------
        try:
            alert_severity_enum = AlertSeverity(event.severity)
        except Exception:
            alert_severity_enum = AlertSeverity.HIGH

        alert_title = f"{event.source_subsystem} Security Event: {event.rule_name}"
        alert_msg = event.description

        alert = Alert(
            threat_id=threat.id,
            device_id=event.device_id,
            title=alert_title,
            message=alert_msg,
            severity=alert_severity_enum,
            status=AlertStatus.UNREAD
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # ----------------------------------------------------
        # Stage 3: Response Engine Auto-Remediation & Stage 4: Audit Logging
        # ----------------------------------------------------
        executed_action = None
        # Auto-response for CRITICAL or HIGH severity events
        if event.severity in ["CRITICAL", "HIGH"]:
            try:
                action_type = None
                params = {}

                if event.source_subsystem == "NETWORK" and event.remote_ip:
                    action_type = response_service.ResponseActionType.BLOCK_IP
                    params = {"remote_ip": event.remote_ip, "remote_port": event.remote_port}
                elif event.pid:
                    action_type = response_service.ResponseActionType.TERMINATE_PROCESS
                    params = {"pid": event.pid, "process_name": event.process_name}

                if action_type:
                    action_obj = response_service.execute_response(
                        db=db,
                        device_id=event.device_id,
                        action_type=action_type,
                        alert_id=alert.id,
                        initiated_by="AUTO_PIPELINE",
                        parameters=params
                    )
                    executed_action = action_obj.action_type.value
            except Exception as resp_err:
                logger.warning(f"[DetectionPipeline] Auto-remediation skipped or already running: {resp_err}")

        # ----------------------------------------------------
        # Stage 5: WebSocket Broadcast
        # ----------------------------------------------------
        event_dict = event.to_dict()
        event_dict.update({
            "threat_id": str(threat.id),
            "alert_id": str(alert.id),
            "risk_score": risk_score,
            "auto_action": executed_action
        })

        broadcast_payload = {
            "event": "DETECTION_EVENT",
            "data": event_dict
        }

        try:
            websocket_manager.broadcast_sync(broadcast_payload)
        except Exception as ws_err:
            logger.warning(f"[DetectionPipeline] WebSocket broadcast failed: {ws_err}")

        return {
            "status": "PROCESSED",
            "event": event_dict,
            "threat_id": threat.id,
            "alert_id": alert.id,
            "risk_score": risk_score,
            "auto_action": executed_action
        }


detection_pipeline = DetectionPipeline()
