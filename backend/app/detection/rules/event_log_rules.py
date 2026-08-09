import re
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, time
from app.models.threat import ThreatSeverity, ThreatType


@dataclass
class EventRuleResult:
    rule_name: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    rule_id: str = "EVT-0000"
    mitre_attack: str = "T1078"
    confidence: float = 90.0


class BaseEventRule:
    """Base class for OS Security Event Detection Rules."""
    rule_name: str
    rule_id: str
    mitre_attack: str = "T1078"
    confidence: float = 90.0
    threat_type: ThreatType
    severity: ThreatSeverity

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        raise NotImplementedError


# -------------------------------------------------------------------------
# Rule 1: Possible Brute Force (Multiple failed logins: e.g., 5 failures in short window)
# -------------------------------------------------------------------------
class BruteForceLogonRule(BaseEventRule):
    """
    Detects multiple failed logon attempts targeting the same account within a short timeframe.
    Threshold: 5 failures within 30 seconds for the same account.
    """
    rule_name = "Possible Brute Force"
    rule_id = "EVT-AUTH-001"
    mitre_attack = "T1110"  # Brute Force
    confidence = 95.0
    threat_type = ThreatType.BRUTE_FORCE_AUTHENTICATION
    severity = ThreatSeverity.CRITICAL

    def __init__(self, failure_threshold: int = 5, window_seconds: int = 30):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_id = str(event.get("event_id", ""))
        event_type = str(event.get("event_type", ""))
        status = str(event.get("status", "")).upper()

        if event_id == "4625" or event_type == "AUTHENTICATION_FAILURE" or status == "FAILED":
            user = event.get("username", "Unknown")
            ip = event.get("ip_address", "Unknown IP")
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=ThreatSeverity.HIGH,
                description=f"Single authentication failure for user '{user}' from IP '{ip}'.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None

    def evaluate_batch(self, events: List[Dict[str, Any]]) -> List[EventRuleResult]:
        results = []
        failures_by_user: Dict[str, List[datetime]] = {}

        for event in events:
            if event.get("event_type") == "AUTHENTICATION_FAILURE" or str(event.get("status")).upper() == "FAILED":
                user = str(event.get("username", "unknown"))
                ts_raw = event.get("timestamp")
                try:
                    if isinstance(ts_raw, str):
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    elif isinstance(ts_raw, datetime):
                        ts = ts_raw
                    else:
                        ts = datetime.now(timezone.utc)
                except Exception:
                    ts = datetime.now(timezone.utc)

                if user not in failures_by_user:
                    failures_by_user[user] = []
                failures_by_user[user].append(ts)

        for user, timestamps in failures_by_user.items():
            if len(timestamps) >= self.failure_threshold:
                timestamps.sort()
                time_span = (timestamps[-1] - timestamps[0]).total_seconds()
                if time_span <= self.window_seconds or len(timestamps) >= self.failure_threshold:
                    results.append(
                        EventRuleResult(
                            rule_name=self.rule_name,
                            threat_type=self.threat_type,
                            severity=self.severity,
                            description=(
                                f"Possible Brute Force detected: {len(timestamps)} failed logon attempts "
                                f"targeting account '{user}' within {int(time_span)}s."
                            ),
                            rule_id=self.rule_id,
                            mitre_attack=self.mitre_attack,
                            confidence=self.confidence
                        )
                    )

        return results


# -------------------------------------------------------------------------
# Rule 2: New Administrator Account (Privilege Escalation)
# -------------------------------------------------------------------------
class NewAdminAccountRule(BaseEventRule):
    """
    Detects creation of a new user account or addition of a user to administrative groups (Event ID 4720, 4732, 4728, GROUP_ADDED).
    """
    rule_name = "New Administrator Account"
    rule_id = "EVT-PRIV-002"
    mitre_attack = "T1078.001"
    confidence = 90.0
    threat_type = ThreatType.PRIVILEGE_ESCALATION
    severity = ThreatSeverity.HIGH

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_id = str(event.get("event_id", ""))
        event_type = str(event.get("event_type", ""))
        desc = str(event.get("description", "")).lower()
        user = event.get("username", "Unknown")

        is_group_added = event_id in ["4732", "4728", "GROUP_ADDED"] or "added to group" in desc
        is_user_created = event_id in ["4720", "USER_CREATED"] or "user account was created" in desc
        is_admin_related = any(k in desc for k in ["admin", "sudo", "wheel", "administrators", "root"])

        if is_group_added or (is_user_created and is_admin_related):
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Privilege Escalation: New administrator account or admin group modification detected for user '{user}'.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


# -------------------------------------------------------------------------
# Rule 3: Account Disabled (Account Management)
# -------------------------------------------------------------------------
class AccountDisabledRule(BaseEventRule):
    """
    Detects account disabling or locking events (Event ID 4725, 4740, ACCOUNT_DISABLED, ACCOUNT_LOCKED).
    """
    rule_name = "Account Disabled"
    rule_id = "EVT-ACCT-003"
    mitre_attack = "T1531"  # Account Access Removal
    confidence = 85.0
    threat_type = ThreatType.UNAUTHORIZED_ACCOUNT_CREATION
    severity = ThreatSeverity.MEDIUM

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_id = str(event.get("event_id", ""))
        desc = str(event.get("description", "")).lower()
        user = event.get("username", "Unknown")

        if event_id in ["4725", "4740", "ACCOUNT_DISABLED", "ACCOUNT_LOCKED"] or "account was disabled" in desc or "locked out" in desc:
            state_label = "locked out" if "4740" in event_id or "locked" in desc else "disabled"
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Account Disabled / Lockout: User account '{user}' was {state_label}.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


# -------------------------------------------------------------------------
# Rule 4: Suspicious Login Time (Configurable off-hours policy, e.g. 03:15 AM)
# -------------------------------------------------------------------------
class SuspiciousLoginTimeRule(BaseEventRule):
    """
    Detects successful logons occurring outside standard business hours (Configurable start/end policy hours).
    Default: Off-hours between 23:00 (11 PM) and 05:00 AM.
    """
    rule_name = "Suspicious Login Time"
    rule_id = "EVT-TIME-004"
    mitre_attack = "T1078"
    confidence = 80.0
    threat_type = ThreatType.SUSPICIOUS_RDP_LOGON
    severity = ThreatSeverity.MEDIUM

    def __init__(self, start_off_hour: int = 23, end_off_hour: int = 5):
        self.start_off_hour = start_off_hour  # 11 PM
        self.end_off_hour = end_off_hour      # 5 AM

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_type = str(event.get("event_type", ""))
        if event_type != "AUTHENTICATION_SUCCESS":
            return None

        ts_raw = event.get("timestamp")
        try:
            if isinstance(ts_raw, str):
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            elif isinstance(ts_raw, datetime):
                dt = ts_raw
            else:
                return None
        except Exception:
            return None

        hour = dt.hour
        # Off-hours check: e.g., hour >= 23 or hour < 5
        is_off_hours = (hour >= self.start_off_hour) or (hour < self.end_off_hour)

        if is_off_hours:
            user = event.get("username", "Unknown")
            formatted_time = dt.strftime("%H:%M:%S UTC")
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Suspicious Login Time: Logon detected for user '{user}' at off-hours ({formatted_time}).",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


# -------------------------------------------------------------------------
# Rule 5: Simultaneous Multi-Device Account Access
# -------------------------------------------------------------------------
class SimultaneousMultiDeviceLoginRule(BaseEventRule):
    """
    Detects multiple devices using the same account simultaneously across different endpoints.
    """
    rule_name = "Simultaneous Multi-Device Account Access"
    rule_id = "EVT-MULTI-005"
    mitre_attack = "T1078"
    confidence = 90.0
    threat_type = ThreatType.SUSPICIOUS_PROCESS_BEHAVIOR
    severity = ThreatSeverity.HIGH

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        return None

    def evaluate_batch(self, events: List[Dict[str, Any]]) -> List[EventRuleResult]:
        results = []
        user_devices: Dict[str, set] = {}

        for event in events:
            if event.get("event_type") == "AUTHENTICATION_SUCCESS":
                user = str(event.get("username", "")).lower()
                device = str(event.get("computer") or event.get("device_id") or "unknown")

                if user and user not in ["system", "unknown", "n/a"]:
                    if user not in user_devices:
                        user_devices[user] = set()
                    user_devices[user].add(device)

        for user, devices in user_devices.items():
            if len(devices) > 1:
                dev_list = ", ".join(list(devices))
                results.append(
                    EventRuleResult(
                        rule_name=self.rule_name,
                        threat_type=self.threat_type,
                        severity=self.severity,
                        description=(
                            f"Simultaneous Account Access: Account '{user}' logged in on {len(devices)} "
                            f"distinct devices simultaneously ({dev_list})."
                        ),
                        rule_id=self.rule_id,
                        mitre_attack=self.mitre_attack,
                        confidence=self.confidence
                    )
                )

        return results


# -------------------------------------------------------------------------
# Legacy Helper Classes
# -------------------------------------------------------------------------
class FailedAuthenticationRule(BruteForceLogonRule):
    pass

class AdminLogonRule(NewAdminAccountRule):
    pass

class RemoteLogonRule(BaseEventRule):
    rule_name = "Remote Desktop / SSH Session Established"
    rule_id = "EVT-AUTH-003"
    mitre_attack = "T1021.001"
    confidence = 90.0
    threat_type = ThreatType.SUSPICIOUS_RDP_LOGON
    severity = ThreatSeverity.HIGH

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        logon_type = str(event.get("logon_type", ""))
        event_id = str(event.get("event_id", ""))
        event_source = str(event.get("event_source", "")).lower()

        is_rdp = "10" in logon_type or "RemoteDesktop" in logon_type
        is_ssh = "ssh" in event_id.lower() or "auth.log" in event_source

        if (is_rdp or is_ssh) and event.get("event_type") == "AUTHENTICATION_SUCCESS":
            user = event.get("username", "Unknown")
            ip = event.get("ip_address", "External IP")
            proto = "RDP" if is_rdp else "SSH"

            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Remote {proto} interactive session established for user '{user}' from IP '{ip}'.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


# =========================================================================
# Phase 4: Persistence & Defense Evasion Detection Rules
# =========================================================================

class NewServiceCreationRule(BaseEventRule):
    """
    Detects creation or installation of new Windows services (Event ID 4697, 7045 or systemd service creation).
    """
    rule_name = "New Windows Service Creation"
    rule_id = "EVT-PERS-006"
    mitre_attack = "T1543.003"  # Create or Modify System Process: Windows Service
    confidence = 90.0
    threat_type = ThreatType.PERSISTENCE_SERVICE_CREATION
    severity = ThreatSeverity.HIGH

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_id = str(event.get("event_id", ""))
        event_type = str(event.get("event_type", ""))
        desc = str(event.get("description", "")).lower()

        is_service_event = (
            event_id in ["4697", "7045", "SERVICE_CREATED"] or
            "service was installed" in desc or
            "service creation" in desc or
            (event_type == "PERSISTENCE" and "service" in desc)
        )

        if is_service_event:
            user = event.get("username", "SYSTEM")
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Persistence Mechanism Detected: New Windows system service created by user '{user}'.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


class ScheduledTaskCreationRule(BaseEventRule):
    """
    Detects creation or modification of scheduled tasks (Event ID 4702, 4698, TASK_CREATED, or cron jobs).
    """
    rule_name = "Scheduled Task Persistence Creation"
    rule_id = "EVT-PERS-007"
    mitre_attack = "T1053.005"  # Scheduled Task/Job: Scheduled Task
    confidence = 90.0
    threat_type = ThreatType.PERSISTENCE_SERVICE_CREATION
    severity = ThreatSeverity.HIGH

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_id = str(event.get("event_id", ""))
        event_type = str(event.get("event_type", ""))
        desc = str(event.get("description", "")).lower()

        is_task_event = (
            event_id in ["4702", "4698", "TASK_CREATED", "CRON_CREATED"] or
            "scheduled task" in desc or
            "task created" in desc or
            (event_type == "PERSISTENCE" and "task" in desc)
        )

        if is_task_event:
            user = event.get("username", "SYSTEM")
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Persistence Mechanism Detected: Scheduled task created/modified by user '{user}'.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


class RegistryRunKeyModificationRule(BaseEventRule):
    """
    Detects Windows Registry Run/RunOnce key modifications for auto-start persistence (Event ID 4657).
    """
    rule_name = "Registry Run Key Persistence Modification"
    rule_id = "EVT-PERS-008"
    mitre_attack = "T1547.001"  # Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
    confidence = 95.0
    threat_type = ThreatType.PERSISTENCE_SERVICE_CREATION
    severity = ThreatSeverity.HIGH

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_id = str(event.get("event_id", ""))
        desc = str(event.get("description", "")).lower()

        is_reg_run = (
            event_id in ["4657", "REG_RUN_MODIFIED"] or
            "software\\microsoft\\windows\\currentversion\\run" in desc or
            "software\\microsoft\\windows\\currentversion\\runonce" in desc or
            "winlogon\\userinit" in desc
        )

        if is_reg_run:
            user = event.get("username", "SYSTEM")
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Persistence Mechanism Detected: Registry auto-run key modified by user '{user}'.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


class StartupFolderModificationRule(BaseEventRule):
    """
    Detects file or link additions to Windows or Linux Startup folders.
    """
    rule_name = "Startup Folder Persistence Modification"
    rule_id = "EVT-PERS-009"
    mitre_attack = "T1547.001"
    confidence = 90.0
    threat_type = ThreatType.FIM_STARTUP_MODIFICATION
    severity = ThreatSeverity.HIGH

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        desc = str(event.get("description", "")).lower()
        event_type = str(event.get("event_type", ""))

        is_startup = (
            "start menu\\programs\\startup" in desc or
            "autostart" in desc or
            "/etc/autostart" in desc or
            event_type == "FIM_STARTUP_MODIFICATION"
        )

        if is_startup:
            user = event.get("username", "Unknown")
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"Persistence Mechanism Detected: File placed in OS Startup Folder by user '{user}'.",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None


class DefenseEvasionLogClearingRule(BaseEventRule):
    """
    Detects clearing or wiping of Security/Audit event logs (Windows Event ID 1102, 104 or Linux log wipe).
    """
    rule_name = "Defense Evasion: Security Audit Log Cleared"
    rule_id = "EVT-EVADE-010"
    mitre_attack = "T1070.001"  # Indicator Removal: Clear Windows Event Logs
    confidence = 100.0
    threat_type = ThreatType.DEFENSE_EVASION_LOG_CLEARING
    severity = ThreatSeverity.CRITICAL

    def evaluate(self, event: Dict[str, Any]) -> Optional[EventRuleResult]:
        event_id = str(event.get("event_id", ""))
        event_type = str(event.get("event_type", ""))
        desc = str(event.get("description", "")).lower()

        is_log_cleared = (
            event_id in ["1102", "104", "LOG_CLEARED"] or
            event_type == "DEFENSE_EVASION" or
            "audit log was cleared" in desc or
            "log cleared" in desc
        )

        if is_log_cleared:
            user = event.get("username", "Administrator")
            return EventRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=f"CRITICAL Defense Evasion: Security audit log was intentionally cleared by user '{user}'. Anti-forensics attempt detected!",
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )
        return None

