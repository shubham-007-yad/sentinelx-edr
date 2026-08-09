from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from app.models.threat import ThreatSeverity, ThreatType
from app.detection.behavior.session import ProcessBehaviorSession
from app.detection.behavior.aggregator import ProcessFileAggregator


# Configurable default list of known ransomware file extensions
DEFAULT_KNOWN_RANSOMWARE_EXTENSIONS: Set[str] = {
    ".locked", ".crypt", ".lock", ".encrypted", ".crypted",
    ".ransom", ".lockbit", ".blackcat", ".clop", ".wannacry",
    ".ryuk", ".revil", ".0x", ".mallox", ".phobos", ".globeimposter"
}


@dataclass
class RansomwareRuleResult:
    rule_id: str
    rule_name: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    score: int
    pid: Optional[int] = None
    process_name: str = "unknown.exe"
    mitre_attack: str = "T1486 — Data Encrypted for Impact"
    confidence: float = 95.0
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.score == 0 and self.severity:
            from app.detection.scoring import threat_scorer
            self.score = threat_scorer.get_severity_score(self.severity)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "threat_type": self.threat_type.value if hasattr(self.threat_type, "value") else str(self.threat_type),
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "description": self.description,
            "score": self.score,
            "pid": self.pid,
            "process_name": self.process_name,
            "mitre_attack": self.mitre_attack,
            "confidence": self.confidence,
            "details": self.details
        }


class BaseRansomwareRule(ABC):
    """Abstract Base Class for Modular Ransomware Behavioral Rules."""
    rule_id: str
    rule_name: str
    mitre_attack: str = "T1486 — Data Encrypted for Impact"
    confidence: float = 95.0

    @abstractmethod
    def evaluate_session(self, session: ProcessBehaviorSession) -> Optional[RansomwareRuleResult]:
        """Evaluates a ProcessBehaviorSession against the ransomware heuristic rule."""
        pass


class MassFileModificationRule(BaseRansomwareRule):
    """
    Rule 1: Mass File Modification
    Flags a process modifying a large number of files within a short observation window.
    Example: 300 files modified within 20 seconds.
    Severity: CRITICAL
    """
    def __init__(self, threshold_count: int = 300, window_seconds: float = 20.0):
        self.rule_id = "RANSOM_MASS_MODIFICATION"
        self.rule_name = "Mass File Modification (Ransomware Burst)"
        self.threshold_count = threshold_count
        self.window_seconds = window_seconds

    def evaluate_session(self, session: ProcessBehaviorSession) -> Optional[RansomwareRuleResult]:
        summary = session.aggregator.get_summary(window_seconds=self.window_seconds)
        modified_count = summary["counts"]["modified"]
        mod_rate = summary["rates_per_second"]["modification_rate"]
        
        # Trigger if modified_count >= threshold (e.g. 300 files in 20s) OR high rate (>= 15 files/sec)
        if modified_count >= self.threshold_count or mod_rate >= 15.0:
            return RansomwareRuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                threat_type=ThreatType.RANSOMWARE_BEHAVIOR,
                severity=ThreatSeverity.CRITICAL,
                description=f"Process {session.process_name} (PID {session.pid}) modified {modified_count} files in {self.window_seconds}s (Rate: {mod_rate} files/s), indicating mass ransomware encryption.",
                score=90,
                pid=session.pid,
                process_name=session.process_name,
                details={
                    "modified_count": modified_count,
                    "window_seconds": self.window_seconds,
                    "modification_rate": mod_rate,
                    "threshold_count": self.threshold_count
                }
            )
        return None


class MassExtensionRenameRule(BaseRansomwareRule):
    """
    Rule 2: Mass Extension Rename
    Flags rapid file extension changes (e.g. .docx -> .docx.locked across multiple files).
    Severity: CRITICAL
    """
    def __init__(self, threshold_renames: int = 10):
        self.rule_id = "RANSOM_MASS_EXTENSION_RENAME"
        self.rule_name = "Mass Extension Mutation & Rename"
        self.threshold_renames = threshold_renames

    def evaluate_session(self, session: ProcessBehaviorSession) -> Optional[RansomwareRuleResult]:
        summary = session.aggregator.get_summary(window_seconds=60.0)
        renamed_count = summary["counts"]["renamed"]
        extension_changes = summary["extension_changes"]

        if renamed_count >= self.threshold_renames or len(extension_changes) > 0:
            total_ext_mutations = sum(extension_changes.values())
            if total_ext_mutations >= 5 or renamed_count >= self.threshold_renames:
                return RansomwareRuleResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    threat_type=ThreatType.RANSOMWARE_BEHAVIOR,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"Process {session.process_name} (PID {session.pid}) rapidly mutated extension names across {renamed_count} files ({extension_changes}).",
                    score=85,
                    pid=session.pid,
                    process_name=session.process_name,
                    details={
                        "renamed_count": renamed_count,
                        "extension_changes": extension_changes,
                        "threshold_renames": self.threshold_renames
                    }
                )
        return None


class EntropyIncreaseRule(BaseRansomwareRule):
    """
    Rule 3: Entropy Increase / High Entropy Burst
    Encrypted files exhibit much higher Shannon entropy than their originals (e.g. > 7.5).
    Severity: CRITICAL
    """
    def __init__(self, entropy_threshold: float = 7.5, min_high_entropy_files: int = 5):
        self.rule_id = "RANSOM_ENTROPY_INCREASE"
        self.rule_name = "High Shannon Entropy Payload Encryption Burst"
        self.entropy_threshold = entropy_threshold
        self.min_high_entropy_files = min_high_entropy_files

    def evaluate_session(self, session: ProcessBehaviorSession) -> Optional[RansomwareRuleResult]:
        high_entropy_count = session.metrics.high_entropy_count
        avg_entropy = session.metrics.avg_entropy

        if high_entropy_count >= self.min_high_entropy_files or avg_entropy >= self.entropy_threshold:
            return RansomwareRuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                threat_type=ThreatType.RANSOMWARE_BEHAVIOR,
                severity=ThreatSeverity.CRITICAL,
                description=f"Process {session.process_name} (PID {session.pid}) modified/created {high_entropy_count} files with high Shannon entropy (Avg Entropy: {avg_entropy}), indicating payload encryption.",
                score=95,
                pid=session.pid,
                process_name=session.process_name,
                details={
                    "high_entropy_count": high_entropy_count,
                    "avg_entropy": avg_entropy,
                    "entropy_threshold": self.entropy_threshold,
                    "min_files": self.min_high_entropy_files
                }
            )
        return None


class DeleteOriginalAfterRewriteRule(BaseRansomwareRule):
    """
    Rule 4: Delete Original After Rewrite
    Typical ransomware workflow: Read file -> Write encrypted version -> Delete original file.
    Severity: HIGH
    """
    def __init__(self, min_deletions: int = 5, min_ratio: float = 0.5):
        self.rule_id = "RANSOM_DELETE_ORIGINAL_REWRITE"
        self.rule_name = "Delete Original Files After Encrypted Rewrite"
        self.min_deletions = min_deletions
        self.min_ratio = min_ratio

    def evaluate_session(self, session: ProcessBehaviorSession) -> Optional[RansomwareRuleResult]:
        deleted_count = session.metrics.file_deleted_count
        deletion_ratio = session.metrics.deletion_to_creation_ratio

        if deleted_count >= self.min_deletions and deletion_ratio >= self.min_ratio:
            return RansomwareRuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                threat_type=ThreatType.RANSOMWARE_BEHAVIOR,
                severity=ThreatSeverity.HIGH,
                description=f"Process {session.process_name} (PID {session.pid}) exhibits original file wipe workflow ({deleted_count} deletions, ratio: {deletion_ratio}).",
                score=75,
                pid=session.pid,
                process_name=session.process_name,
                details={
                    "deleted_count": deleted_count,
                    "deletion_to_creation_ratio": deletion_ratio,
                    "min_deletions": self.min_deletions,
                    "min_ratio": self.min_ratio
                }
            )
        return None


class KnownRansomwareExtensionRule(BaseRansomwareRule):
    """
    Rule 5: Known Ransomware Extensions
    Flags process writing/renaming files to known ransomware extensions (.locked, .crypt, .lock, .encrypted, etc.).
    Configurable list of extensions.
    Severity: CRITICAL
    """
    def __init__(self, custom_extensions: Optional[Set[str]] = None):
        self.rule_id = "RANSOM_KNOWN_EXTENSION"
        self.rule_name = "Known Ransomware Extension Usage"
        self.known_extensions = custom_extensions if custom_extensions is not None else DEFAULT_KNOWN_RANSOMWARE_EXTENSIONS

    def add_extension(self, extension: str):
        """Adds a runtime extension to the monitored set."""
        ext = extension.lower() if extension.startswith(".") else f".{extension.lower()}"
        self.known_extensions.add(ext)

    def evaluate_session(self, session: ProcessBehaviorSession) -> Optional[RansomwareRuleResult]:
        summary = session.aggregator.get_summary(window_seconds=60.0)
        ext_changes = summary["extension_changes"]
        
        matched_exts = set()
        for ext_key in ext_changes:
            target_ext = ext_key.split("->")[-1]
            if target_ext in self.known_extensions:
                matched_exts.add(target_ext)

        if session.metrics.known_ransomware_ext_count >= 1 or len(matched_exts) > 0:
            return RansomwareRuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                threat_type=ThreatType.KNOWN_MALWARE,
                severity=ThreatSeverity.CRITICAL,
                description=f"Process {session.process_name} (PID {session.pid}) modified/renamed files to known ransomware extensions: {list(matched_exts or DEFAULT_KNOWN_RANSOMWARE_EXTENSIONS)[:5]}.",
                score=100,
                pid=session.pid,
                process_name=session.process_name,
                details={
                    "matched_extensions": list(matched_exts),
                    "known_ransomware_ext_count": session.metrics.known_ransomware_ext_count
                }
            )
        return None


class RansomwareRuleEngine:
    """
    Modular Rule Engine executing all registered ransomware rules against a process behavior session.
    """
    def __init__(self, rules: Optional[List[BaseRansomwareRule]] = None):
        self.rules: List[BaseRansomwareRule] = rules or [
            MassFileModificationRule(),
            MassExtensionRenameRule(),
            EntropyIncreaseRule(),
            DeleteOriginalAfterRewriteRule(),
            KnownRansomwareExtensionRule()
        ]

    def evaluate_all(self, session: ProcessBehaviorSession) -> List[RansomwareRuleResult]:
        """Evaluates all rules against the given session and returns triggered results."""
        results: List[RansomwareRuleResult] = []
        for rule in self.rules:
            try:
                res = rule.evaluate_session(session)
                if res:
                    results.append(res)
            except Exception as e:
                print(f"Error evaluating rule {rule.rule_id}: {e}")
        return results
