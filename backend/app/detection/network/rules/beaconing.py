from typing import Optional, List, Dict, Tuple
import time
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.network.base import BaseNetworkRule, NetworkRuleResult


class BeaconingDetectionRule(BaseNetworkRule):
    """
    Behavioral rule detecting periodic C2 beaconing patterns (repeated connections at fixed time intervals
    e.g., every 60 seconds from the same process to the same remote IP address).
    """

    rule_name: str = "C2 Network Beaconing Detected"
    rule_id: str = "NET-RULE-0005"
    rule_version: str = "1.0.0"
    mitre_attack: str = "T1071"
    confidence: float = 95.0
    threat_type: ThreatType = ThreatType.C2_BEACONING
    severity: ThreatSeverity = ThreatSeverity.HIGH

    def __init__(self, min_samples: int = 3, max_interval_variance: float = 15.0):
        self.min_samples = min_samples
        self.max_interval_variance = max_interval_variance
        # Cache connection history: (process_name, remote_ip) -> List[float timestamp_epochs]
        self._history: Dict[Tuple[str, str], List[float]] = {}

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
    ) -> Optional[NetworkRuleResult]:
        if not process_name or not remote_ip:
            return None

        key = (process_name.lower(), remote_ip)
        now = time.time()

        if key not in self._history:
            self._history[key] = [now]
            return None

        timestamps = self._history[key]
        timestamps.append(now)

        # Keep max 10 recent timestamps for window
        if len(timestamps) > 10:
            timestamps = timestamps[-10:]
            self._history[key] = timestamps

        if len(timestamps) < self.min_samples:
            return None

        # Calculate time intervals between consecutive connections
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        avg_interval = sum(intervals) / len(intervals)

        # Calculate interval variance / deviations
        variances = [abs(itv - avg_interval) for itv in intervals]
        max_dev = max(variances) if variances else 0.0

        # If connections occur at regular intervals (variance within threshold), flag beaconing
        if max_dev <= self.max_interval_variance and avg_interval >= 0.0:
            desc = (
                f"C2 Beaconing Pattern Detected: Process '{process_name}' (PID {pid}) "
                f"exhibits periodic network beaconing to remote IP {remote_ip}:{remote_port} "
                f"(Average interval: ~{avg_interval:.1f}s | Variance: ±{max_dev:.1f}s | Samples: {len(timestamps)})."
            )
            return NetworkRuleResult(
                rule_name=self.rule_name,
                threat_type=self.threat_type,
                severity=self.severity,
                description=desc,
                pid=pid,
                process_name=process_name,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                state=state,
                rule_id=self.rule_id,
                mitre_attack=self.mitre_attack,
                confidence=self.confidence
            )

        return None
