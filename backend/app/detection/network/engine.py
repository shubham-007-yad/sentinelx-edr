from typing import List, Optional, Dict, Any, Tuple
from app.detection.network.base import BaseNetworkRule, NetworkRuleResult
from app.detection.network.rules.suspicious_port import SuspiciousPortRule
from app.detection.network.rules.blacklisted_ip import BlacklistedIPRule
from app.detection.network.rules.excessive_conns import ExcessiveConnectionsRule
from app.detection.network.rules.unexpected_internet import UnexpectedInternetAccessRule
from app.detection.network.rules.beaconing import BeaconingDetectionRule


class NetworkDetectionEngine:
    """
    Dedicated Network Threat Detection Rule Engine for SentinelX EDR.
    Evaluates endpoint network telemetry streams against registered detection rules.
    """

    def __init__(self, rules: Optional[List[BaseNetworkRule]] = None):
        if rules is None:
            self.rules: List[BaseNetworkRule] = [
                SuspiciousPortRule(),
                BlacklistedIPRule(),
                ExcessiveConnectionsRule(),
                UnexpectedInternetAccessRule(),
                BeaconingDetectionRule(),
            ]
        else:
            self.rules = list(rules)

    def register_rule(self, rule: BaseNetworkRule) -> None:
        """Dynamically registers a new network detection rule at runtime."""
        self.rules.append(rule)

    def evaluate_connection(
        self,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_port: Optional[int] = None,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        protocol: str = "TCP",
        state: Optional[str] = None
    ) -> List[NetworkRuleResult]:
        """
        Evaluates a single network connection socket against all registered rules.
        Returns list of NetworkRuleResult objects for matching threat rules.
        """
        findings: List[NetworkRuleResult] = []
        for rule in self.rules:
            result = rule.evaluate_connection(
                pid=pid,
                process_name=process_name,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                state=state
            )
            if result is not None:
                findings.append(result)
        return findings

    def evaluate_connection_batch(
        self,
        connections: List[Dict[str, Any]]
    ) -> List[NetworkRuleResult]:
        """
        Evaluates a batch of network connection telemetry records.
        Runs single connection evaluation as well as batch-level excessive connection aggregation.
        """
        findings: List[NetworkRuleResult] = []

        # Track connection counts per (pid, process_name) for ExcessiveConnectionsRule
        pid_counts: Dict[Tuple[int, str], int] = {}
        pid_sample_conn: Dict[Tuple[int, str], Dict[str, Any]] = {}

        for conn in connections:
            pid = conn.get("pid")
            process_name = conn.get("process_name") or "unknown"
            local_ip = conn.get("local_ip")
            local_port = conn.get("local_port")
            remote_ip = conn.get("remote_ip")
            remote_port = conn.get("remote_port")
            protocol = conn.get("protocol", "TCP")
            state = conn.get("state")

            # Evaluate single connection against rules
            single_findings = self.evaluate_connection(
                pid=pid,
                process_name=process_name,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                state=state
            )
            findings.extend(single_findings)

            if pid and process_name:
                key = (pid, process_name)
                pid_counts[key] = pid_counts.get(key, 0) + 1
                if key not in pid_sample_conn:
                    pid_sample_conn[key] = conn

        # Evaluate ExcessiveConnectionsRule across batch
        for rule in self.rules:
            if isinstance(rule, ExcessiveConnectionsRule):
                for (pid, process_name), count in pid_counts.items():
                    sample = pid_sample_conn.get((pid, process_name))
                    res = rule.evaluate_process_connections(
                        pid=pid,
                        process_name=process_name,
                        connection_count=count,
                        sample_connection=sample
                    )
                    if res is not None:
                        findings.append(res)

        return findings
