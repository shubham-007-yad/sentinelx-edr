"""
Business & Executive Security Metrics Module
Computes high-level security indicators, endpoint risk scores, MTTA, MTTR, SLA compliance,
and explicit signal-weighted risk scoring with contributing factors and recommended actions.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.threat import Threat, ThreatStatus, ThreatSeverity, ThreatType
from app.models.device import Device, DeviceStatus
from app.models.response_action import ResponseAction, ResponseActionStatus


class BusinessMetricsCalculator:
    def __init__(self, db: Session):
        self.db = db

    def calculate_top_executive_metrics(self) -> Dict[str, Any]:
        """
        Calculates top executive metrics:
        - Total Endpoints
        - Online Endpoints
        - Total Incidents (Total Alerts)
        - Critical Incidents (Critical Severity Alerts)
        - Threats Today
        - Alerts Today
        - Responses Executed (Successful Response Actions)
        - Average Response Time (MTTR in minutes)
        """
        total_endpoints = self.db.query(Device).count()
        online_endpoints = self.db.query(Device).filter(Device.status == DeviceStatus.ONLINE).count()

        total_incidents = self.db.query(Alert).count()
        critical_incidents = self.db.query(Alert).filter(Alert.severity == AlertSeverity.CRITICAL).count()

        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        threats_today = self.db.query(Threat).filter(Threat.detected_at >= today_start).count()
        alerts_today = self.db.query(Alert).filter(Alert.created_at >= today_start).count()

        responses_executed = self.db.query(ResponseAction).filter(
            ResponseAction.status == ResponseActionStatus.SUCCESS
        ).count()

        response_metrics = self.calculate_response_time_metrics(timeframe_days=30)
        avg_response_time = response_metrics.get("mttr_minutes", 0.0)

        return {
            "total_endpoints": total_endpoints,
            "online_endpoints": online_endpoints,
            "total_incidents": total_incidents,
            "critical_incidents": critical_incidents,
            "threats_today": threats_today,
            "alerts_today": alerts_today,
            "responses_executed": responses_executed,
            "average_response_time_minutes": avg_response_time,
        }

    def calculate_endpoint_risk_scores(self, timeframe_days: int = 30) -> List[Dict[str, Any]]:
        """
        Calculates a dynamic risk score (0 to 100) for every registered device
        based on explicit risk signals:
        - Critical Alerts (+40 per critical alert)
        - Ransomware Behavior (+25)
        - IOC Matches (+20)
        - Suspicious PowerShell / CMD (+15)
        - FIM / Privilege Escalation (+15)
        - Unresolved Threats (+10 per unresolved threat)
        - Isolated / Offline status (+15 penalty)

        Outputs contributing factors and recommended analyst response actions.
        """
        devices = self.db.query(Device).all()
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=timeframe_days)

        results = []
        for dev in devices:
            alerts = self.db.query(Alert).filter(
                Alert.device_id == dev.id,
                Alert.created_at >= start_time
            ).all()

            threats = self.db.query(Threat).join(Alert).filter(
                Alert.device_id == dev.id,
                Threat.detected_at >= start_time
            ).all()

            unresolved_threats = [t for t in threats if t.status != ThreatStatus.RESOLVED]

            raw_score = 0.0
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0

            contributing_factors = []
            recommended_actions = []

            # 1. Alert Severities (Critical Alerts = +40 points)
            for alert in alerts:
                if alert.severity == AlertSeverity.CRITICAL:
                    critical_count += 1
                    raw_score += 40.0
                    contributing_factors.append({
                        "signal": "Critical Severity Alert",
                        "weight": 40,
                        "detail": alert.title
                    })
                elif alert.severity == AlertSeverity.HIGH:
                    high_count += 1
                    raw_score += 20.0
                    contributing_factors.append({
                        "signal": "High Severity Alert",
                        "weight": 20,
                        "detail": alert.title
                    })
                elif alert.severity == AlertSeverity.MEDIUM:
                    medium_count += 1
                    raw_score += 10.0
                    contributing_factors.append({
                        "signal": "Medium Severity Alert",
                        "weight": 10,
                        "detail": alert.title
                    })
                elif alert.severity == AlertSeverity.LOW:
                    low_count += 1
                    raw_score += 2.0

            # 2. Specific High-Risk Threat Types
            has_ransomware = False
            has_ioc_match = False
            has_powershell = False

            for threat in threats:
                tt = threat.threat_type
                if tt in [ThreatType.RANSOMWARE_BEHAVIOR, ThreatType.FIM_MASS_FILE_MODIFICATION]:
                    if not has_ransomware:
                        has_ransomware = True
                        raw_score += 25.0
                        contributing_factors.append({
                            "signal": "Ransomware Behavior",
                            "weight": 25,
                            "detail": threat.rule_name
                        })
                        recommended_actions.append("Isolate host from network immediately to prevent lateral spread")

                if tt in [ThreatType.KNOWN_MALWARE, ThreatType.BLACK_LISTED_IP, ThreatType.C2_BEACONING]:
                    if not has_ioc_match:
                        has_ioc_match = True
                        raw_score += 20.0
                        contributing_factors.append({
                            "signal": "IOC Match",
                            "weight": 20,
                            "detail": threat.rule_name
                        })
                        recommended_actions.append("Perform full antimalware & memory scan")

                if tt in [ThreatType.SUSPICIOUS_POWERSHELL, ThreatType.SUSPICIOUS_CMD, ThreatType.LOLBIN_ABUSE]:
                    if not has_powershell:
                        has_powershell = True
                        raw_score += 15.0
                        contributing_factors.append({
                            "signal": "Suspicious Script Execution",
                            "weight": 15,
                            "detail": threat.rule_name
                        })
                        recommended_actions.append("Inspect obfuscated script command lines & parent process tree")

            # 3. Unresolved Threats (+10 per unresolved threat)
            if len(unresolved_threats) > 0:
                unresolved_score = len(unresolved_threats) * 10.0
                raw_score += unresolved_score
                contributing_factors.append({
                    "signal": "Unresolved Threats",
                    "weight": int(unresolved_score),
                    "detail": f"{len(unresolved_threats)} threat(s) currently open"
                })
                recommended_actions.append("Assign SOC analyst to resolve pending threat cases")

            # 4. Containment Status Penalty
            if dev.status == DeviceStatus.ISOLATED:
                raw_score += 15.0
                contributing_factors.append({
                    "signal": "Network Isolation Penalty",
                    "weight": 15,
                    "detail": "Endpoint currently isolated"
                })
            elif dev.status == DeviceStatus.OFFLINE and (critical_count + high_count) > 0:
                raw_score += 10.0
                contributing_factors.append({
                    "signal": "Offline High-Risk Endpoint",
                    "weight": 10,
                    "detail": "Device offline with uncontained critical/high alerts"
                })

            # Clamp score between 0 and 100
            score = round(min(100.0, raw_score), 1)

            if score >= 85.0:
                risk_level = "CRITICAL RISK"
            elif score >= 60.0:
                risk_level = "HIGH RISK"
            elif score >= 30.0:
                risk_level = "MEDIUM RISK"
            else:
                risk_level = "LOW RISK"

            if not recommended_actions:
                recommended_actions.append("Routine endpoint monitoring")

            results.append({
                "device_id": str(dev.id),
                "hostname": dev.hostname,
                "ip_address": dev.ip_address,
                "status": dev.status.value if hasattr(dev.status, 'value') else str(dev.status),
                "os_type": dev.os_type.value if hasattr(dev.os_type, 'value') else str(dev.os_type),
                "risk_score": score,
                "risk_level": risk_level,
                "active_alerts_count": len(alerts),
                "unresolved_threats": len(unresolved_threats),
                "alert_breakdown": {
                    "critical": critical_count,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count,
                },
                "contributing_factors": contributing_factors,
                "recommended_actions": list(dict.fromkeys(recommended_actions)),
                "last_seen": dev.last_seen.isoformat() if dev.last_seen else None
            })

        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    def calculate_response_time_metrics(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """
        Calculates MTTA (Mean Time to Acknowledge in minutes),
        MTTR (Mean Time to Respond in minutes), and SLA compliance percentages.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=timeframe_days)

        acknowledged_alerts = self.db.query(Alert).filter(
            Alert.created_at >= start_time,
            Alert.acknowledged_at.isnot(None)
        ).all()

        mtta_seconds = []
        for alert in acknowledged_alerts:
            if alert.created_at and alert.acknowledged_at:
                delta = (alert.acknowledged_at - alert.created_at).total_seconds()
                if delta >= 0:
                    mtta_seconds.append(delta)

        avg_mtta_minutes = round(sum(mtta_seconds) / len(mtta_seconds) / 60.0, 2) if mtta_seconds else 0.0

        response_actions = self.db.query(ResponseAction).join(Alert).filter(
            ResponseAction.started_at >= start_time,
            ResponseAction.status == ResponseActionStatus.SUCCESS,
            ResponseAction.completed_at.isnot(None)
        ).all()

        mttr_seconds = []
        for ra in response_actions:
            ref_time = ra.alert.created_at if (ra.alert and ra.alert.created_at) else ra.started_at
            if ra.completed_at and ref_time:
                delta = (ra.completed_at - ref_time).total_seconds()
                if delta >= 0:
                    mttr_seconds.append(delta)

        avg_mttr_minutes = round(sum(mttr_seconds) / len(mttr_seconds) / 60.0, 2) if mttr_seconds else 0.0

        mtta_sla_met = sum(1 for sec in mtta_seconds if sec <= 900)
        mttr_sla_met = sum(1 for sec in mttr_seconds if sec <= 3600)

        mtta_sla_percent = round((mtta_sla_met / len(mtta_seconds) * 100.0), 1) if mtta_seconds else 100.0
        mttr_sla_percent = round((mttr_sla_met / len(mttr_seconds) * 100.0), 1) if mttr_seconds else 100.0

        return {
            "mtta_minutes": avg_mtta_minutes,
            "mttr_minutes": avg_mttr_minutes,
            "mtta_sla_compliance_percent": mtta_sla_percent,
            "mttr_sla_compliance_percent": mttr_sla_percent,
            "acknowledged_count": len(mtta_seconds),
            "responded_count": len(mttr_seconds),
        }

    def calculate_security_posture_overview(self, timeframe_days: int = 7) -> Dict[str, Any]:
        """Calculates executive high-level security metrics and device status summary."""
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=timeframe_days)

        total_devices = self.db.query(Device).count()
        online_devices = self.db.query(Device).filter(Device.status == DeviceStatus.ONLINE).count()
        isolated_devices = self.db.query(Device).filter(Device.status == DeviceStatus.ISOLATED).count()
        offline_devices = self.db.query(Device).filter(Device.status == DeviceStatus.OFFLINE).count()

        total_threats = self.db.query(Threat).filter(Threat.detected_at >= start_time).count()
        resolved_threats = self.db.query(Threat).filter(
            Threat.detected_at >= start_time,
            Threat.status == ThreatStatus.RESOLVED
        ).count()
        resolution_rate = round((resolved_threats / total_threats * 100.0), 1) if total_threats > 0 else 100.0

        auto_responses = self.db.query(ResponseAction).filter(
            ResponseAction.started_at >= start_time,
            ResponseAction.initiated_by == "AUTOMATIC"
        ).count()
        total_responses = self.db.query(ResponseAction).filter(
            ResponseAction.started_at >= start_time
        ).count()
        auto_containment_rate = round((auto_responses / total_responses * 100.0), 1) if total_responses > 0 else 0.0

        return {
            "total_monitored_endpoints": total_devices,
            "online_endpoints": online_devices,
            "isolated_endpoints": isolated_devices,
            "offline_endpoints": offline_devices,
            "total_threats_detected": total_threats,
            "resolved_threats": resolved_threats,
            "threat_resolution_rate": resolution_rate,
            "automated_containment_rate": auto_containment_rate,
            "total_response_actions": total_responses,
        }
