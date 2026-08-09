from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from app.detection.behavior.session import ProcessBehaviorSession


@dataclass
class CorrelationMatch:
    """
    Result of a multi-event behavioral sequence match.
    """
    rule_id: str
    rule_name: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    matched_sequence: List[Dict[str, Any]]
    confidence: float = 95.0
    mitre_tactic: str = "T1486 — Data Encrypted for Impact"
    risk_contribution: float = 30.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "matched_sequence_length": len(self.matched_sequence),
            "confidence": self.confidence,
            "mitre_tactic": self.mitre_tactic,
            "risk_contribution": self.risk_contribution
        }


class BehaviorCorrelationRules:
    """
    Evaluates temporal multi-event sequences across a ProcessBehaviorSession.
    Instead of single-event triggers, detects complex multi-stage ransomware attack behaviors.
    """

    @staticmethod
    def evaluate_all(session: ProcessBehaviorSession) -> List[CorrelationMatch]:
        """Runs all correlation rules on a process session."""
        matches: List[CorrelationMatch] = []
        
        # 1. Mass High-Entropy Write Sequence
        match1 = BehaviorCorrelationRules.check_mass_entropy_sequence(session)
        if match1:
            matches.append(match1)

        # 2. Shadow Copy Wipe + File Mutation Sequence
        match2 = BehaviorCorrelationRules.check_shadow_copy_sequence(session)
        if match2:
            matches.append(match2)

        # 3. Extension Renaming & Original File Deletion Sequence
        match3 = BehaviorCorrelationRules.check_rename_delete_sequence(session)
        if match3:
            matches.append(match3)

        # 4. Ransom Note Drop Sequence
        match4 = BehaviorCorrelationRules.check_ransom_note_sequence(session)
        if match4:
            matches.append(match4)

        # 5. C2 Network Connection Concurrent with Encryption
        match5 = BehaviorCorrelationRules.check_network_c2_encryption_sequence(session)
        if match5:
            matches.append(match5)

        return matches

    @staticmethod
    def check_mass_entropy_sequence(session: ProcessBehaviorSession) -> Optional[CorrelationMatch]:
        """Detects rapid succession of high-entropy file writes."""
        m = session.metrics
        if m.high_entropy_count >= 5:
            high_entropy_events = [ev for ev in session.events_sequence if ev.get("entropy", 0) >= 7.5]
            return CorrelationMatch(
                rule_id="CORR_MASS_ENTROPY_BURST",
                rule_name="Mass High-Entropy File Encryption Burst Sequence",
                severity="CRITICAL",
                description=f"Process {session.process_name} (PID {session.pid}) modified/created {m.high_entropy_count} high-entropy encrypted files (Entropy >= 7.5) within window.",
                matched_sequence=high_entropy_events,
                confidence=98.0,
                mitre_tactic="T1486 — Data Encrypted for Impact",
                risk_contribution=35.0
            )
        return None

    @staticmethod
    def check_shadow_copy_sequence(session: ProcessBehaviorSession) -> Optional[CorrelationMatch]:
        """Detects shadow copy / recovery destruction followed by or accompanying file mutations."""
        m = session.metrics
        if m.shadow_copy_deleted and m.total_file_mutations >= 1:
            shadow_events = [ev for ev in session.events_sequence if ev.get("flagged_reason") == "SHADOW_COPY_DESTRUCTION"]
            return CorrelationMatch(
                rule_id="CORR_SHADOW_COPY_WIPE",
                rule_name="Volume Shadow Copy Destruction + File Mutation Sequence",
                severity="CRITICAL",
                description=f"Process {session.process_name} (PID {session.pid}) executed shadow copy wipe commands followed by file mutations.",
                matched_sequence=shadow_events,
                confidence=99.0,
                mitre_tactic="T1490 — Inhibit System Recovery",
                risk_contribution=30.0
            )
        return None

    @staticmethod
    def check_rename_delete_sequence(session: ProcessBehaviorSession) -> Optional[CorrelationMatch]:
        """Detects mass extension renames accompanied by original file deletions."""
        m = session.metrics
        if m.file_renamed_count >= 3 and m.file_deleted_count >= 2:
            rename_events = [ev for ev in session.events_sequence if ev.get("event_type") in ["FILE_RENAMED", "FILE_DELETED"]]
            return CorrelationMatch(
                rule_id="CORR_EXTENSION_RENAME_SWAP",
                rule_name="Rapid Extension Swap & Original File Wipe Sequence",
                severity="HIGH",
                description=f"Process {session.process_name} (PID {session.pid}) rapidly swapped file extensions ({m.file_renamed_count} renames) and wiped original files ({m.file_deleted_count} deletions).",
                matched_sequence=rename_events,
                confidence=92.0,
                mitre_tactic="T1486 — Data Encrypted for Impact",
                risk_contribution=25.0
            )
        return None

    @staticmethod
    def check_ransom_note_sequence(session: ProcessBehaviorSession) -> Optional[CorrelationMatch]:
        """Detects ransom note creation during file write bursts."""
        m = session.metrics
        if m.ransom_note_count >= 1:
            note_events = [ev for ev in session.events_sequence if "RANSOM_NOTE" in str(ev.get("flagged_reason"))]
            return CorrelationMatch(
                rule_id="CORR_RANSOM_NOTE_DROP",
                rule_name="Ransom Note Creation Sequence",
                severity="HIGH",
                description=f"Process {session.process_name} (PID {session.pid}) dropped ransom notes ({m.ransom_note_count} note files detected).",
                matched_sequence=note_events,
                confidence=95.0,
                mitre_tactic="T1486 — Data Encrypted for Impact",
                risk_contribution=20.0
            )
        return None

    @staticmethod
    def check_network_c2_encryption_sequence(session: ProcessBehaviorSession) -> Optional[CorrelationMatch]:
        """Detects outbound network connection concurrent with high-entropy file writes."""
        m = session.metrics
        if m.network_connection_count >= 1 and m.high_entropy_count >= 2:
            net_events = [ev for ev in session.events_sequence if ev.get("event_type") in ["NETWORK_CONNECT", "SOCKET_OUTBOUND"]]
            return CorrelationMatch(
                rule_id="CORR_C2_CONCURRENT_ENCRYPTION",
                rule_name="C2 Beaconing Concurrent with File Encryption",
                severity="CRITICAL",
                description=f"Process {session.process_name} (PID {session.pid}) initiated outbound network socket connections concurrently with high entropy file encryption.",
                matched_sequence=net_events,
                confidence=96.0,
                mitre_tactic="T1071 — Application Layer Protocol / T1486 — Data Encrypted for Impact",
                risk_contribution=30.0
            )
        return None
