import math
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Computes Shannon Entropy H(X) in bits per byte [0.0 - 8.0].
    H(X) = - sum( p(x) * log2(p(x)) )
    - Plaintext / Code / Documents: typical entropy 2.5 - 6.5
    - Encrypted / Compressed Binary Data: typical entropy 7.5 - 8.0
    """
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


KNOWN_RANSOMWARE_EXTENSIONS = {
    ".locked", ".crypto", ".enc", ".crypted", ".ransom", ".lockbit",
    ".blackcat", ".clop", ".0x", ".lock", ".encrypted", ".darkside",
    ".revil", ".ryuk", ".wannacry", ".mallox", ".phobos", ".globeimposter"
}

RANSOM_NOTE_PATTERNS = [
    "read_me.txt", "readme.txt", "readme.html", "how_to_decrypt.html",
    "decrypt_files.txt", "restore_files.txt", "readme_restore.txt",
    "@readme_restore.txt", "how_to_recover.txt", "help_decrypt.txt"
]


@dataclass
class BehavioralMetrics:
    """
    Aggregated real-time behavioral metrics for a process or system session.
    Tracks velocity, entropy spikes, file mutations, ransom notes, and defense evasion commands.
    """
    file_modified_count: int = 0
    file_created_count: int = 0
    file_deleted_count: int = 0
    file_renamed_count: int = 0
    
    high_entropy_count: int = 0         # Files with Shannon Entropy >= 7.5
    medium_entropy_count: int = 0       # Files with Shannon Entropy 6.0 - 7.5
    total_entropy_sum: float = 0.0      # Accumulated sum for average calculation
    entropy_samples_count: int = 0
    
    ransom_note_count: int = 0          # Number of dropped ransom notes
    known_ransomware_ext_count: int = 0  # Number of files given ransomware extensions
    shadow_copy_deleted: bool = False   # True if vssadmin / wbadmin / bcdedit shadow wipe detected
    
    network_connection_count: int = 0   # Outbound connections created during file burst
    window_duration_seconds: float = 60.0

    def record_entropy(self, entropy_val: float):
        """Records an entropy measurement."""
        self.total_entropy_sum += entropy_val
        self.entropy_samples_count += 1
        if entropy_val >= 7.5:
            self.high_entropy_count += 1
        elif entropy_val >= 6.0:
            self.medium_entropy_count += 1

    @property
    def avg_entropy(self) -> float:
        """Returns the average Shannon entropy across sampled files."""
        if self.entropy_samples_count == 0:
            return 0.0
        return round(self.total_entropy_sum / self.entropy_samples_count, 4)

    @property
    def total_file_mutations(self) -> int:
        """Total filesystem mutations (modified + created + deleted + renamed)."""
        return self.file_modified_count + self.file_created_count + self.file_deleted_count + self.file_renamed_count

    @property
    def encryption_velocity(self) -> float:
        """Files mutated per second within the active observation window."""
        if self.window_duration_seconds <= 0:
            return 0.0
        return round(self.total_file_mutations / self.window_duration_seconds, 2)

    @property
    def deletion_to_creation_ratio(self) -> float:
        """Ratio of file deletions relative to file creations/modifications."""
        base_writes = self.file_created_count + self.file_modified_count
        if base_writes == 0:
            return 0.0
        return round(self.file_deleted_count / base_writes, 2)

    def calculate_composite_risk_score(self) -> float:
        """
        Calculates a composite Ransomware Risk Score from 0.0 to 100.0.
        Weighted indicators:
        - High Entropy Spikes (>= 7.5): up to 30 pts
        - Mass File Extension Renames / Velocity: up to 25 pts
        - Shadow Copy / Defense Evasion: 25 pts
        - Ransom Note Creation: up to 20 pts
        - High Deletion Burst Ratio: up to 15 pts
        """
        score = 0.0
        
        # 1. High Entropy Spikes (Max 30 pts)
        if self.high_entropy_count >= 10:
            score += 30.0
        elif self.high_entropy_count >= 5:
            score += 22.0
        elif self.high_entropy_count >= 2:
            score += 12.0
        elif self.high_entropy_count >= 1:
            score += 5.0

        # 2. Extension Mutations & Velocity (Max 25 pts)
        if self.known_ransomware_ext_count >= 3:
            score += 25.0
        elif self.known_ransomware_ext_count >= 1:
            score += 15.0
        
        if self.file_renamed_count >= 10:
            score += 15.0
        elif self.file_renamed_count >= 5:
            score += 8.0

        # 3. Shadow Copy / Backup Wipe (Max 25 pts)
        if self.shadow_copy_deleted:
            score += 25.0

        # 4. Ransom Note Drop (Max 20 pts)
        if self.ransom_note_count >= 2:
            score += 20.0
        elif self.ransom_note_count == 1:
            score += 12.0

        # 5. Original File Deletion Burst (Max 15 pts)
        if self.file_deleted_count >= 10 and self.deletion_to_creation_ratio >= 0.5:
            score += 15.0
        elif self.file_deleted_count >= 5:
            score += 8.0

        return min(100.0, round(score, 2))

    @property
    def severity(self) -> str:
        """Derives severity string from calculated composite risk score."""
        score = self.calculate_composite_risk_score()
        if score >= 75.0:
            return "CRITICAL"
        elif score >= 50.0:
            return "HIGH"
        elif score >= 25.0:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_modified_count": self.file_modified_count,
            "file_created_count": self.file_created_count,
            "file_deleted_count": self.file_deleted_count,
            "file_renamed_count": self.file_renamed_count,
            "total_file_mutations": self.total_file_mutations,
            "high_entropy_count": self.high_entropy_count,
            "medium_entropy_count": self.medium_entropy_count,
            "avg_entropy": self.avg_entropy,
            "ransom_note_count": self.ransom_note_count,
            "known_ransomware_ext_count": self.known_ransomware_ext_count,
            "shadow_copy_deleted": self.shadow_copy_deleted,
            "network_connection_count": self.network_connection_count,
            "encryption_velocity": self.encryption_velocity,
            "deletion_to_creation_ratio": self.deletion_to_creation_ratio,
            "composite_risk_score": self.calculate_composite_risk_score(),
            "severity": self.severity
        }
