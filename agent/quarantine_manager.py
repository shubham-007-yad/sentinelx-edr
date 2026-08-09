import os
import json
import shutil
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional
from file_hasher import calculate_sha256

logger = logging.getLogger(__name__)

DEFAULT_QUARANTINE_DIR = os.environ.get("SENTINELX_QUARANTINE_DIR", os.path.join(os.getcwd(), ".quarantine"))


class QuarantineRecord:
    """Represents quarantine metadata for a secured threat file."""
    def __init__(
        self,
        original_path: str,
        quarantine_path: str,
        timestamp: str,
        sha256: str,
        reason: str
    ):
        self.original_path = original_path
        self.quarantine_path = quarantine_path
        self.timestamp = timestamp
        self.sha256 = sha256
        self.reason = reason

    def to_dict(self) -> dict:
        return {
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "timestamp": self.timestamp,
            "sha256": self.sha256,
            "reason": self.reason
        }

    @classmethod
    def from_dict(cls, data: dict) -> "QuarantineRecord":
        return cls(
            original_path=data.get("original_path", ""),
            quarantine_path=data.get("quarantine_path", ""),
            timestamp=data.get("timestamp", ""),
            sha256=data.get("sha256", ""),
            reason=data.get("reason", "")
        )


class QuarantineManager:
    """
    Manages endpoint file isolation instead of immediate deletion.
    Moves suspicious/malicious files into .quarantine/ and tracks metadata manifest.
    """

    def __init__(self, quarantine_dir: Optional[str] = None):
        self.quarantine_dir = os.path.abspath(quarantine_dir or DEFAULT_QUARANTINE_DIR)
        self.manifest_path = os.path.join(self.quarantine_dir, "manifest.json")
        self._ensure_quarantine_dir()

    def _ensure_quarantine_dir(self):
        """Creates quarantine directory and manifest file if absent."""
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            if not os.path.exists(self.manifest_path):
                with open(self.manifest_path, "w") as f:
                    json.dump([], f, indent=2)
        except Exception as e:
            logger.error(f"[QuarantineManager] Failed to setup quarantine dir '{self.quarantine_dir}': {e}")

    def _load_manifest(self) -> List[dict]:
        """Loads entries from manifest.json."""
        if not os.path.exists(self.manifest_path):
            return []
        try:
            with open(self.manifest_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"[QuarantineManager] Failed to read manifest file: {e}")
            return []

    def _save_manifest(self, records: List[dict]):
        """Persists manifest entries to disk."""
        try:
            with open(self.manifest_path, "w") as f:
                json.dump(records, f, indent=2)
        except Exception as e:
            logger.error(f"[QuarantineManager] Failed to write manifest file: {e}")

    def quarantine_file(
        self,
        file_path: str,
        reason: str = "Threat detected during USB scan",
        sha256: Optional[str] = None
    ) -> Optional[QuarantineRecord]:
        """
        Moves file to .quarantine/ directory, strips permissions, and records metadata manifest.
        Tracks:
        - Original path
        - Quarantine path
        - Timestamp
        - SHA-256
        - Reason
        """
        if not file_path or not os.path.exists(file_path):
            logger.error(f"[QuarantineManager] File does not exist for quarantine: {file_path}")
            return None

        abs_file_path = os.path.abspath(file_path)

        # 1. Calculate SHA-256 if not provided
        if not sha256:
            try:
                sha256 = calculate_sha256(abs_file_path)
            except Exception as e:
                logger.warning(f"[QuarantineManager] Could not calculate SHA-256 for {file_path}: {e}")
                sha256 = "UNKNOWN_HASH"

        # 2. Generate unique quarantine destination filename
        now = datetime.now(timezone.utc)
        ts_str = now.strftime("%Y%m%d_%H%M%S")
        basename = os.path.basename(abs_file_path)
        dest_filename = f"{ts_str}_{sha256[:8]}_{basename}"
        dest_path = os.path.join(self.quarantine_dir, dest_filename)

        try:
            # 3. Move file to quarantine vault
            shutil.move(abs_file_path, dest_path)

            # 4. Strip permissions to disable execution
            try:
                os.chmod(dest_path, 000)
            except Exception as chmod_err:
                logger.warning(f"[QuarantineManager] Permission strip failed for {dest_path}: {chmod_err}")

            # 5. Create quarantine record
            record = QuarantineRecord(
                original_path=abs_file_path,
                quarantine_path=dest_path,
                timestamp=now.isoformat(),
                sha256=sha256,
                reason=reason
            )

            # 6. Update manifest index
            manifest = self._load_manifest()
            manifest.append(record.to_dict())
            self._save_manifest(manifest)

            logger.info(
                f"[QuarantineManager AUDIT] Quarantined '{abs_file_path}' -> '{dest_path}'. "
                f"SHA256: {sha256}, Reason: {reason}"
            )
            return record

        except Exception as e:
            logger.error(f"[QuarantineManager] Error quarantining file '{file_path}': {e}")
            return None

    def list_quarantined_files(self) -> List[QuarantineRecord]:
        """Returns all quarantined file records from manifest."""
        entries = self._load_manifest()
        return [QuarantineRecord.from_dict(item) for item in entries]

    def get_record_by_hash(self, sha256: str) -> Optional[QuarantineRecord]:
        """Retrieves a quarantine record by SHA-256 hash."""
        records = self.list_quarantined_files()
        for r in records:
            if r.sha256 == sha256:
                return r
        return None
