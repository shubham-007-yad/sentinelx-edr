from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from app.detection.behavior.session import ProcessBehaviorSession
from app.models.threat import ThreatSeverity


@dataclass
class EvidenceItem:
    """Individual behavioral evidence item contributing to the correlation score."""
    indicator: str           # e.g., "Mass rename", "Entropy increase", "Original deletion", "High file count"
    score: int               # Score points awarded
    max_score: int           # Maximum possible score for this indicator
    details: str
    triggered: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "score": self.score,
            "max_score": self.max_score,
            "details": self.details,
            "triggered": self.triggered
        }


@dataclass
class CorrelationScoreReport:
    """
    Unified multi-vector correlation score report.
    Combines evidence across filesystem actions, entropy math, extension swaps, and deletion ratios.
    """
    total_score: int
    severity: ThreatSeverity
    pid: Optional[int]
    process_name: str
    evidence_breakdown: List[EvidenceItem]
    automated_isolation_recommended: bool = False
    terminate_process_recommended: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": self.total_score,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "pid": self.pid,
            "process_name": self.process_name,
            "evidence_breakdown": [e.to_dict() for e in self.evidence_breakdown],
            "automated_isolation_recommended": self.automated_isolation_recommended,
            "terminate_process_recommended": self.terminate_process_recommended
        }


class RansomwareCorrelationScorer:
    """
    Ransomware Behavioral Correlation Scorer.
    Combines multi-vector evidence instead of relying on a single isolated rule:
    - Mass rename (up to 35 pts)
    - Entropy increase (up to 30 pts)
    - Original file deletion (up to 20 pts)
    - High file count / velocity (up to 15 pts)
    - Shadow copy / recovery wipe bonus (+25 pts)
    - Known ransomware extension bonus (+30 pts)
    """

    def __init__(
        self,
        weight_mass_rename: int = 35,
        weight_entropy_increase: int = 30,
        weight_original_deletion: int = 20,
        weight_high_file_count: int = 15
    ):
        self.weight_mass_rename = weight_mass_rename
        self.weight_entropy_increase = weight_entropy_increase
        self.weight_original_deletion = weight_original_deletion
        self.weight_high_file_count = weight_high_file_count

    def calculate_correlation_score(self, session: ProcessBehaviorSession) -> CorrelationScoreReport:
        evidence_list: List[EvidenceItem] = []
        accumulated_score = 0
        
        m = session.metrics
        agg_summary = session.aggregator.get_summary(window_seconds=60.0)

        # 1. Mass Rename Evidence (Max 35 pts)
        renamed_count = agg_summary["counts"]["renamed"]
        ext_mutations = sum(agg_summary["extension_changes"].values())
        
        if renamed_count >= 10 or ext_mutations >= 5:
            score = self.weight_mass_rename
            evidence_list.append(EvidenceItem(
                indicator="Mass rename",
                score=score,
                max_score=self.weight_mass_rename,
                details=f"Detected {renamed_count} file renames with {ext_mutations} extension mutations ({agg_summary['extension_changes']})."
            ))
            accumulated_score += score
        elif renamed_count >= 3 or ext_mutations >= 1:
            score = int(self.weight_mass_rename * 0.5)
            evidence_list.append(EvidenceItem(
                indicator="Mass rename",
                score=score,
                max_score=self.weight_mass_rename,
                details=f"Partial rename activity detected ({renamed_count} renames)."
            ))
            accumulated_score += score

        # 2. Entropy Increase Evidence (Max 30 pts)
        high_entropy_count = m.high_entropy_count
        avg_entropy = m.avg_entropy
        
        if high_entropy_count >= 5 or avg_entropy >= 7.5:
            score = self.weight_entropy_increase
            evidence_list.append(EvidenceItem(
                indicator="Entropy increase",
                score=score,
                max_score=self.weight_entropy_increase,
                details=f"Modified {high_entropy_count} files with high Shannon entropy >= 7.5 (Avg: {avg_entropy})."
            ))
            accumulated_score += score
        elif high_entropy_count >= 1 or avg_entropy >= 6.5:
            score = int(self.weight_entropy_increase * 0.5)
            evidence_list.append(EvidenceItem(
                indicator="Entropy increase",
                score=score,
                max_score=self.weight_entropy_increase,
                details=f"Moderate entropy elevation detected ({high_entropy_count} high-entropy files, Avg: {avg_entropy})."
            ))
            accumulated_score += score

        # 3. Original File Deletion Evidence (Max 20 pts)
        deleted_count = m.file_deleted_count
        del_ratio = m.deletion_to_creation_ratio
        
        if deleted_count >= 5 and del_ratio >= 0.5:
            score = self.weight_original_deletion
            evidence_list.append(EvidenceItem(
                indicator="Original deletion",
                score=score,
                max_score=self.weight_original_deletion,
                details=f"Wiped {deleted_count} original files following creations (Deletion ratio: {del_ratio})."
            ))
            accumulated_score += score
        elif deleted_count >= 2:
            score = int(self.weight_original_deletion * 0.5)
            evidence_list.append(EvidenceItem(
                indicator="Original deletion",
                score=score,
                max_score=self.weight_original_deletion,
                details=f"Wiped {deleted_count} files."
            ))
            accumulated_score += score

        # 4. High File Count / Velocity Evidence (Max 15 pts)
        total_mutations = agg_summary["total_records_in_window"]
        mod_rate = agg_summary["rates_per_second"]["modification_rate"]
        
        if total_mutations >= 50 or mod_rate >= 5.0:
            score = self.weight_high_file_count
            evidence_list.append(EvidenceItem(
                indicator="High file count",
                score=score,
                max_score=self.weight_high_file_count,
                details=f"High mutation velocity ({total_mutations} files in window, Rate: {mod_rate} files/sec)."
            ))
            accumulated_score += score
        elif total_mutations >= 15:
            score = int(self.weight_high_file_count * 0.5)
            evidence_list.append(EvidenceItem(
                indicator="High file count",
                score=score,
                max_score=self.weight_high_file_count,
                details=f"Moderate file count mutation ({total_mutations} files)."
            ))
            accumulated_score += score

        # Bonus: Shadow Copy Wipe (+25 pts)
        if m.shadow_copy_deleted:
            score = 25
            evidence_list.append(EvidenceItem(
                indicator="Shadow copy destruction",
                score=score,
                max_score=25,
                details="Executed shadow copy / recovery catalog deletion command."
            ))
            accumulated_score += score

        # Bonus: Known Ransomware Extension (+30 pts)
        if m.known_ransomware_ext_count >= 1:
            score = 30
            evidence_list.append(EvidenceItem(
                indicator="Known ransomware extension",
                score=score,
                max_score=30,
                details=f"Applied known ransomware extensions to {m.known_ransomware_ext_count} files."
            ))
            accumulated_score += score

        total_score = min(100, accumulated_score)

        # Derive Severity
        if total_score >= 80:
            severity = ThreatSeverity.CRITICAL
        elif total_score >= 50:
            severity = ThreatSeverity.HIGH
        elif total_score >= 25:
            severity = ThreatSeverity.MEDIUM
        else:
            severity = ThreatSeverity.LOW

        recommend_containment = total_score >= 80

        return CorrelationScoreReport(
            total_score=total_score,
            severity=severity,
            pid=session.pid,
            process_name=session.process_name,
            evidence_breakdown=evidence_list,
            automated_isolation_recommended=recommend_containment,
            terminate_process_recommended=recommend_containment
        )
