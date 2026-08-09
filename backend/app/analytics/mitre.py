"""
MITRE ATT&CK Framework Mapping & Analytics Module
Maps SentinelX threat types and alert rules to standard MITRE ATT&CK Tactics and Techniques,
providing matrix heatmaps, tactic breakdowns, technique frequencies, and coverage percentages.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from app.models.threat import Threat, ThreatType

# 12 Core Enterprise MITRE ATT&CK Tactics
STANDARD_MITRE_TACTICS: List[Dict[str, str]] = [
    {"tactic_id": "TA0001", "tactic_name": "Initial Access"},
    {"tactic_id": "TA0002", "tactic_name": "Execution"},
    {"tactic_id": "TA0003", "tactic_name": "Persistence"},
    {"tactic_id": "TA0004", "tactic_name": "Privilege Escalation"},
    {"tactic_id": "TA0005", "tactic_name": "Defense Evasion"},
    {"tactic_id": "TA0006", "tactic_name": "Credential Access"},
    {"tactic_id": "TA0007", "tactic_name": "Discovery"},
    {"tactic_id": "TA0008", "tactic_name": "Lateral Movement"},
    {"tactic_id": "TA0009", "tactic_name": "Collection"},
    {"tactic_id": "TA0011", "tactic_name": "Command and Control"},
    {"tactic_id": "TA0010", "tactic_name": "Exfiltration"},
    {"tactic_id": "TA0040", "tactic_name": "Impact"},
]

# Canonical MITRE ATT&CK Mappings for SentinelX Threat Types
MITRE_ATTACK_MAP: Dict[str, Dict[str, str]] = {
    "KNOWN_MALWARE": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1204",
        "technique_name": "User Execution",
    },
    "DOUBLE_EXTENSION": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1036.007",
        "technique_name": "Double Extension",
    },
    "HIDDEN_EXECUTABLE": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1564.001",
        "technique_name": "Hidden Files and Directories",
    },
    "AUTORUN_SCRIPT": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
    },
    "SUSPICIOUS_EXTENSION": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1036",
        "technique_name": "Masquerading",
    },
    "ANOMALOUS_FILE": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1036",
        "technique_name": "Masquerading",
    },
    "SUSPICIOUS_POWERSHELL": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
    },
    "SUSPICIOUS_CMD": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
    },
    "LOLBIN_ABUSE": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1218",
        "technique_name": "System Binary Proxy Execution",
    },
    "SUSPICIOUS_PROCESS_BEHAVIOR": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
    },
    "SUSPICIOUS_NETWORK_PORT": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port",
    },
    "BLACK_LISTED_IP": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    "EXCESSIVE_CONNECTIONS": {
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
    },
    "UNEXPECTED_INTERNET_ACCESS": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    "C2_BEACONING": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
    },
    "FIM_EXECUTABLE_IN_DOWNLOADS": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
    },
    "FIM_DOUBLE_EXTENSION_MASQUERADE": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1036.007",
        "technique_name": "Double Extension",
    },
    "FIM_STARTUP_MODIFICATION": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
    },
    "FIM_MASS_FILE_MODIFICATION": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
    },
    "BRUTE_FORCE_AUTHENTICATION": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "PRIVILEGE_ESCALATION": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
    },
    "UNAUTHORIZED_ACCOUNT_CREATION": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1136",
        "technique_name": "Create Account",
    },
    "DEFENSE_EVASION_LOG_CLEARING": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070.001",
        "technique_name": "Clear Windows Event Logs",
    },
    "SUSPICIOUS_RDP_LOGON": {
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "technique_id": "T1021.001",
        "technique_name": "Remote Desktop Protocol",
    },
    "PERSISTENCE_SERVICE_CREATION": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
    },
    "RANSOMWARE_BEHAVIOR": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
    },
}

DEFAULT_MITRE_MAPPING = {
    "tactic_id": "TA0005",
    "tactic_name": "Defense Evasion",
    "technique_id": "T1036",
    "technique_name": "Uncategorized Suspicious Activity",
}


class MitreMapper:
    def __init__(self, db: Session):
        self.db = db

    def get_mapping_for_type(self, threat_type_str: str) -> Dict[str, str]:
        """Returns canonical MITRE mapping for a given ThreatType string."""
        return MITRE_ATTACK_MAP.get(threat_type_str, DEFAULT_MITRE_MAPPING)

    def analyze_mitre_attack_coverage(
        self, timeframe_days: int = 30, limit_techniques: int = 10
    ) -> Dict[str, Any]:
        """
        Aggregates observed threats into MITRE Tactics and Techniques
        and returns detailed breakdowns for executive dashboards.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=timeframe_days)

        threats = self.db.query(Threat).filter(Threat.detected_at >= start_time).all()

        tactic_counts: Dict[str, Dict[str, Any]] = {}
        technique_counts: Dict[str, Dict[str, Any]] = {}
        total_mappings = len(threats)

        for threat in threats:
            tt_str = threat.threat_type.value if hasattr(threat.threat_type, 'value') else str(threat.threat_type)
            mapping = self.get_mapping_for_type(tt_str)

            tac_id = mapping["tactic_id"]
            tac_name = mapping["tactic_name"]
            tech_id = mapping["technique_id"]
            tech_name = mapping["technique_name"]

            # Aggregate Tactic
            if tac_id not in tactic_counts:
                tactic_counts[tac_id] = {
                    "tactic_id": tac_id,
                    "tactic_name": tac_name,
                    "count": 0,
                }
            tactic_counts[tac_id]["count"] += 1

            # Aggregate Technique
            if tech_id not in technique_counts:
                technique_counts[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic_id": tac_id,
                    "tactic_name": tac_name,
                    "count": 0,
                }
            technique_counts[tech_id]["count"] += 1

        top_tactics = sorted(tactic_counts.values(), key=lambda x: x["count"], reverse=True)
        top_techniques = sorted(technique_counts.values(), key=lambda x: x["count"], reverse=True)[:limit_techniques]

        for tac in top_tactics:
            tac["percentage"] = round((tac["count"] / total_mappings * 100.0), 1) if total_mappings > 0 else 0.0

        for tech in top_techniques:
            tech["percentage"] = round((tech["count"] / total_mappings * 100.0), 1) if total_mappings > 0 else 0.0

        # Calculate Coverage Percentage
        observed_tactics_count = len(tactic_counts)
        tactic_coverage_percent = round((observed_tactics_count / len(STANDARD_MITRE_TACTICS) * 100.0), 1)

        total_rules_defined = len(MITRE_ATTACK_MAP)
        distinct_rule_techniques = len({v["technique_id"] for v in MITRE_ATTACK_MAP.values()})
        technique_detection_coverage_percent = round((len(technique_counts) / distinct_rule_techniques * 100.0), 1) if distinct_rule_techniques > 0 else 0.0

        return {
            "timeframe_days": timeframe_days,
            "total_observed_threats": total_mappings,
            "tactic_coverage_percent": tactic_coverage_percent,
            "technique_coverage_percent": technique_detection_coverage_percent,
            "observed_tactics_count": observed_tactics_count,
            "total_framework_tactics": len(STANDARD_MITRE_TACTICS),
            "tactics_breakdown": top_tactics,
            "top_techniques": top_techniques,
        }

    def get_mitre_matrix_heatmap(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """
        Generates full MITRE ATT&CK Matrix Heatmap payload organized by 12 Core Tactics.
        Calculates cell heat scores (0-100) and heat levels for UI Matrix visualization.
        """
        coverage_data = self.analyze_mitre_attack_coverage(timeframe_days=timeframe_days, limit_techniques=100)
        total_threats = coverage_data["total_observed_threats"]

        # Build technique map per tactic from canonical rules
        tactic_techniques_map: Dict[str, Dict[str, Dict[str, Any]]] = {
            t["tactic_id"]: {} for t in STANDARD_MITRE_TACTICS
        }

        for rule in MITRE_ATTACK_MAP.values():
            tac_id = rule["tactic_id"]
            tech_id = rule["technique_id"]
            tech_name = rule["technique_name"]

            if tac_id in tactic_techniques_map:
                if tech_id not in tactic_techniques_map[tac_id]:
                    tactic_techniques_map[tac_id][tech_id] = {
                        "technique_id": tech_id,
                        "technique_name": tech_name,
                        "detection_count": 0,
                        "heat_score": 0.0,
                        "heat_level": "INACTIVE"
                    }

        # Populate detection counts from DB threats
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=timeframe_days)
        threats = self.db.query(Threat).filter(Threat.detected_at >= start_time).all()

        for threat in threats:
            tt_str = threat.threat_type.value if hasattr(threat.threat_type, 'value') else str(threat.threat_type)
            mapping = self.get_mapping_for_type(tt_str)
            tac_id = mapping["tactic_id"]
            tech_id = mapping["technique_id"]

            if tac_id in tactic_techniques_map:
                if tech_id in tactic_techniques_map[tac_id]:
                    tactic_techniques_map[tac_id][tech_id]["detection_count"] += 1

        # Max count for scaling heat scores
        all_counts = [cell["detection_count"] for tac in tactic_techniques_map.values() for cell in tac.values()]
        max_count = max(all_counts) if all_counts and max(all_counts) > 0 else 1

        # Construct Matrix Heatmap Columns
        matrix_columns = []
        for tactic_info in STANDARD_MITRE_TACTICS:
            tac_id = tactic_info["tactic_id"]
            tac_name = tactic_info["tactic_name"]
            tech_cells = list(tactic_techniques_map[tac_id].values())

            tactic_total = sum(c["detection_count"] for c in tech_cells)

            for cell in tech_cells:
                cnt = cell["detection_count"]
                heat_score = round((cnt / max_count) * 100.0, 1) if max_count > 0 else 0.0
                cell["heat_score"] = heat_score

                if cnt >= 15 or heat_score >= 75.0:
                    cell["heat_level"] = "CRITICAL"
                elif cnt >= 5 or heat_score >= 40.0:
                    cell["heat_level"] = "HIGH"
                elif cnt >= 1 or heat_score > 0.0:
                    cell["heat_level"] = "MEDIUM"
                else:
                    cell["heat_level"] = "INACTIVE"

            # Sort cells by detection_count desc
            tech_cells.sort(key=lambda x: x["detection_count"], reverse=True)

            matrix_columns.append({
                "tactic_id": tac_id,
                "tactic_name": tac_name,
                "total_detections": tactic_total,
                "active_techniques_count": sum(1 for c in tech_cells if c["detection_count"] > 0),
                "total_monitored_techniques": len(tech_cells),
                "techniques": tech_cells
            })

        return {
            "timeframe_days": timeframe_days,
            "total_observed_threats": total_threats,
            "tactic_coverage_percent": coverage_data["tactic_coverage_percent"],
            "technique_coverage_percent": coverage_data["technique_coverage_percent"],
            "top_tactics": coverage_data["tactics_breakdown"],
            "technique_frequency": coverage_data["top_techniques"],
            "matrix_columns": matrix_columns,
        }
