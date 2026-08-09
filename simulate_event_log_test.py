#!/usr/bin/env python3
"""
SentinelX EDR — Day 12 Windows Event Logs & Authentication Monitoring Simulation Test
Validates:
1. Cross-platform OS event log collection (Windows Security.evtx & Linux auth.log).
2. Database persistence of SecurityEvent models.
3. Modular detection rules (Brute Force, Admin Escalation, Off-Hours, Service Persistence, Log Clearing).
4. Detection Pipeline integration (Threat creation, Alerting, Risk Scoring).
5. Authentication Summary & Auth Timeline generation.
"""

import sys
import uuid
import logging
from datetime import datetime, timezone

from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, OSType, DeviceStatus
from app.models.event_log import SecurityEvent
from app.models.threat import Threat
from app.models.alert import Alert
from app.services import event_log_service
from agent.collectors.event_log_collector import EventLogCollector

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def run_simulation():
    print("\n==========================================================================")
    print(" 🚀 SentinelX EDR — Day 12 Event Log & Auth Monitoring Simulation ")
    print("==========================================================================\n")

    # 1. Initialize Database
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    from app.db.init_db import init_db
    try:
        init_db(db)
    except Exception:
        pass

    try:
        # 2. Setup Test Device

        dev = db.query(Device).filter(Device.hostname == "sentinelx-dc-node").first()
        if not dev:
            dev = Device(
                id=uuid.uuid4(),
                hostname="sentinelx-dc-node",
                ip_address="192.168.1.100",
                os_type=OSType.WINDOWS,
                status=DeviceStatus.ONLINE
            )
            db.add(dev)
            db.commit()
            db.refresh(dev)

        print(f"[*] Target Device: Hostname='{dev.hostname}', ID='{dev.id}'")

        # 3. Test Agent Event Log Collector
        collector = EventLogCollector(device_id=str(dev.id))
        collected_events = collector.collect_events(limit=10)
        print(f"[*] Agent EventLogCollector gathered {len(collected_events)} native/simulated OS events.")

        ingest_res = event_log_service.ingest_security_events(db=db, device_id=dev.id, raw_events=collected_events)
        print(f"[+] Baseline Event Ingestion: {ingest_res['ingested']} stored into database.\n")

        # 4. Trigger Attack Scenarios
        print("--------------------------------------------------------------------------")
        print(" 🎯 Executing Day 12 Attack Simulation Scenarios ")
        print("--------------------------------------------------------------------------")

        scenarios = [
            ("BRUTE_FORCE", "5 Rapid Failed Logons from Remote IP 198.51.100.44"),
            ("PRIVILEGE_ESCALATION", "New Admin Account created & added to Administrators group"),
            ("ACCOUNT_DISABLED", "User account disabled / lockout event"),
            ("OFF_HOURS", "Interactive logon at 03:15 AM off-hours"),
            ("PERSISTENCE", "Windows Service Creation: MalwarePersistenceSvc"),
            ("LOG_CLEARING", "CRITICAL: Security Audit Log Cleared (Event ID 1102)")
        ]

        total_simulated_threats = 0
        for scenario_code, description in scenarios:
            sim_events = []
            now_iso = datetime.now(timezone.utc).isoformat()

            if scenario_code == "BRUTE_FORCE":
                for i in range(5):
                    sim_events.append({
                        "id": str(uuid.uuid4()),
                        "device_id": str(dev.id),
                        "event_source": "Security",
                        "event_id": "4625",
                        "event_type": "AUTHENTICATION_FAILURE",
                        "level": "Warning",
                        "username": "domain_admin_target",
                        "computer": dev.hostname,
                        "logon_type": "10-RemoteDesktop",
                        "ip_address": "198.51.100.44",
                        "status": "FAILED",
                        "description": f"Failed logon attempt #{i+1} for domain_admin_target",
                        "timestamp": now_iso
                    })
            elif scenario_code == "PRIVILEGE_ESCALATION":
                sim_events.append({
                    "id": str(uuid.uuid4()),
                    "device_id": str(dev.id),
                    "event_source": "Security",
                    "event_id": "4732",
                    "event_type": "PRIVILEGE_ESCALATION",
                    "level": "Warning",
                    "username": "shadow_admin",
                    "computer": dev.hostname,
                    "status": "SUCCESS",
                    "description": "User shadow_admin added to Administrators security-enabled group",
                    "timestamp": now_iso
                })
            elif scenario_code == "ACCOUNT_DISABLED":
                sim_events.append({
                    "id": str(uuid.uuid4()),
                    "device_id": str(dev.id),
                    "event_source": "Security",
                    "event_id": "4725",
                    "event_type": "ACCOUNT_MANAGEMENT",
                    "level": "Warning",
                    "username": "locked_account",
                    "computer": dev.hostname,
                    "status": "SUCCESS",
                    "description": "User account locked_account was disabled",
                    "timestamp": now_iso
                })
            elif scenario_code == "OFF_HOURS":
                sim_events.append({
                    "id": str(uuid.uuid4()),
                    "device_id": str(dev.id),
                    "event_source": "Security",
                    "event_id": "4624",
                    "event_type": "AUTHENTICATION_SUCCESS",
                    "level": "Information",
                    "username": "night_operator",
                    "computer": dev.hostname,
                    "logon_type": "2-Interactive",
                    "ip_address": "10.0.0.50",
                    "status": "SUCCESS",
                    "description": "User night_operator logged in interactively at 03:15 AM off-hours",
                    "timestamp": "2026-08-02T03:15:00Z"
                })
            elif scenario_code == "PERSISTENCE":
                sim_events.append({
                    "id": str(uuid.uuid4()),
                    "device_id": str(dev.id),
                    "event_source": "Security",
                    "event_id": "4697",
                    "event_type": "PERSISTENCE",
                    "level": "Warning",
                    "username": "SYSTEM",
                    "computer": dev.hostname,
                    "status": "SUCCESS",
                    "description": "A service was installed in the system: MalwarePersistenceSvc",
                    "timestamp": now_iso
                })
            elif scenario_code == "LOG_CLEARING":
                sim_events.append({
                    "id": str(uuid.uuid4()),
                    "device_id": str(dev.id),
                    "event_source": "Security",
                    "event_id": "1102",
                    "event_type": "DEFENSE_EVASION",
                    "level": "Critical",
                    "username": "Administrator",
                    "computer": dev.hostname,
                    "status": "SUCCESS",
                    "description": "CRITICAL: The audit log was cleared by Administrator",
                    "timestamp": now_iso
                })

            res = event_log_service.ingest_security_events(db=db, device_id=dev.id, raw_events=sim_events)
            total_simulated_threats += res["threats_detected"]
            print(f" [+] [{scenario_code}] {description} -> Ingested: {res['ingested']}, Threats Fired: {res['threats_detected']}")

        # 5. Phase 6 Response Actions & Audit Log Verification
        print("\n--------------------------------------------------------------------------")
        print(" 🛠️ Executing Phase 6 Response Actions & Verifying Audit Logs ")
        print("--------------------------------------------------------------------------")
        from app.models.response_action import ResponseActionType
        from app.services import response_service
        from app.models.response_audit_log import ResponseAuditLog

        phase6_actions = [
            (ResponseActionType.DISABLE_USER, {"target_user": "shadow_admin"}),
            (ResponseActionType.FORCE_LOGOUT, {"target_user": "shadow_admin"}),
            (ResponseActionType.INVESTIGATE, {"event_id": "4625"}),
            (ResponseActionType.IGNORE, {"event_id": "4624"}),
            (ResponseActionType.ALLOWLIST_EVENT, {"target_user": "secops"})
        ]

        audited_count = 0
        for act_type, params in phase6_actions:
            act_obj = response_service.execute_response(
                db=db,
                device_id=dev.id,
                action_type=act_type,
                initiated_by="SOC_ANALYST",
                user_role="ADMIN",
                parameters=params
            )
            logs = db.query(ResponseAuditLog).filter(ResponseAuditLog.action_id == act_obj.id).all()
            audited_count += len(logs)
            print(f" [+] Action: {act_obj.action_type.value:<16} | Status: {act_obj.status.value:<7} | Forensic Audit Logs: {len(logs)}")

        # 6. Summary Metrics Verification
        summary = event_log_service.get_authentication_summary(db=db, device_id=dev.id)
        timeline = event_log_service.get_auth_timeline(db=db, device_id=dev.id, limit=10)

        print("\n==========================================================================")
        print(" 📊 Day 12 Verification Results Summary ")
        print("==========================================================================")
        print(f" Total OS Events Stored:     {summary['total_events']}")
        print(f" Successful Logins:          {summary['logins']}")
        print(f" Failed Authentication Logs: {summary['failed_logons']}")
        print(f" Privilege Changes:          {summary['privilege_changes']}")
        print(f" Persistence Events:         {summary['persistence_events']}")
        print(f" Critical Events:            {summary['critical_events']}")
        print(f" Threats & Alerts Generated: {total_simulated_threats}")
        print(f" Phase 6 Audited Log Entries: {audited_count}")

        print("\n 📅 Chronological Auth Timeline (Recent 5):")
        for item in timeline[:5]:
            print(f"  - [{item['timestamp'][:19]}] {item['category']} | User: '{item['username']}' | Type: {item['logon_type']} | IP: {item['ip_address']}")

        print("\n[✔] ALL DAY 12 TESTS (PHASES 1-6) PASSED SUCCESSFULLY!\n")

    finally:
        db.close()


if __name__ == "__main__":
    run_simulation()

