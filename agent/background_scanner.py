import os
import queue
import threading
import time
from typing import Optional, List, Dict, Any
from logger import logger
from usb_scanner import USBScanner
from file_metadata import FileMetadataCollector
from quarantine_manager import QuarantineManager
from api.client import APIClient

DEFAULT_USB_POLICY: Dict[str, Any] = {
    "enable_usb_monitoring": True,
    "enable_auto_scanning": True,
    "scan_removable_only": True,
    "max_file_size_mb": 50,
    "ignored_extensions": [".tmp", ".log", ".bak", ".sys"],
    "enable_sha256_hashing": True,
    "block_unauthorized_usbs": False,
    "auto_quarantine_suspicious": False,
    "allowed_vendor_ids": [],
    "read_only_mode": False
}

DANGEROUS_EXTENSIONS = {".exe", ".dll", ".vbs", ".ps1", ".bat", ".sh", ".cmd", ".scr", ".jar", ".sys"}


class USBScanPipelineWorker:
    """
    Automated Background USB Scan Pipeline Worker with Dynamic Policy Engine Integration.
    Asynchronously handles file enumeration, policy filtering (ignored extensions, max file size),
    metadata collection, SHA-256 hashing, auto-quarantine, and batch uploads to backend.
    """

    def __init__(self, api_client: APIClient, batch_size: int = 50, policy: Optional[Dict[str, Any]] = None):
        self.api_client = api_client
        self.batch_size = batch_size
        self.metadata_collector = FileMetadataCollector()
        self.quarantine_manager = QuarantineManager()
        self.scan_queue: queue.Queue = queue.Queue()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        self.policy: Dict[str, Any] = dict(DEFAULT_USB_POLICY)
        if policy:
            self.policy.update(policy)

    def update_policy(self, new_policy: Dict[str, Any]):
        """Dynamically updates active USB security policy."""
        logger.info(f"[USBScanPipelineWorker] Applying updated USB security policy configuration.")
        self.policy.update(new_policy)

    def start(self):
        """Starts background worker thread for processing USB scan tasks."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self._worker_thread.start()
        logger.info("[USBScanPipelineWorker] Background scan worker thread started.")

    def stop(self):
        """Stops background worker thread."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)

    def enqueue_scan(self, usb_event_id: str, drive_letter: str):
        """Pushes a USB event scan task to the background queue if policy permits."""
        if not self.policy.get("enable_usb_monitoring", True):
            logger.info(f"[USBScanPipelineWorker Policy] USB monitoring disabled by policy. Skipping event '{usb_event_id}'.")
            return

        if not self.policy.get("enable_auto_scanning", True):
            logger.info(f"[USBScanPipelineWorker Policy] Automatic USB scanning disabled by policy. Skipping event '{usb_event_id}'.")
            return

        logger.info(f"[USBScanPipelineWorker] Enqueueing automated scan task for event '{usb_event_id}' on drive '{drive_letter}'.")
        self.scan_queue.put((usb_event_id, drive_letter))

    def process_scan_task(self, usb_event_id: str, drive_letter: str) -> Dict[str, Any]:
        """
        Executes complete scan pipeline for a single USB event synchronously according to policy:
        Enumerate Files -> Policy Filters (Ext, Size) -> Metadata & SHA-256 -> Auto-Quarantine -> Batch Upload.
        """
        if not self.policy.get("enable_usb_monitoring", True) or not self.policy.get("enable_auto_scanning", True):
            logger.warning("[USBScanPipelineWorker Policy] USB monitoring or auto-scanning is disabled.")
            return {"scanned_count": 0, "uploaded_count": 0, "errors": 0, "skipped_policy_count": 0}

        drive_path = os.path.abspath(drive_letter.rstrip('\\') + '\\') if os.name == 'nt' else drive_letter
        if not os.path.exists(drive_path):
            logger.error(f"[USBScanPipelineWorker] Target drive path does not exist: {drive_path}")
            return {"scanned_count": 0, "uploaded_count": 0, "errors": 1, "skipped_policy_count": 0}

        logger.info(f"🔍 [Automated Scan Pipeline] Starting file scan on drive '{drive_path}' for USB event ID: {usb_event_id}")

        # 1. Enumerate files
        scanner = USBScanner(drive_path)
        file_paths = scanner.enumerate_files()
        logger.info(f"📂 [Enumeration Complete] Discovered {len(file_paths)} files on {drive_path}.")

        scanned_results: List[Dict[str, Any]] = []
        uploaded_total = 0
        skipped_policy_count = 0
        quarantined_count = 0

        # Policy parameters
        max_bytes = self.policy.get("max_file_size_mb", 50) * 1024 * 1024
        ignored_exts = set(ext.lower() for ext in self.policy.get("ignored_extensions", []))
        enable_hashing = self.policy.get("enable_sha256_hashing", True)
        auto_quarantine = self.policy.get("auto_quarantine_suspicious", False)

        # 2 & 3. Filter & Collect Metadata + SHA-256 Hashing according to policy
        for idx, fp in enumerate(file_paths, 1):
            ext = os.path.splitext(fp)[1].lower()

            # Ignore extensions check
            if ext in ignored_exts:
                skipped_policy_count += 1
                logger.debug(f"[Policy Filter] Ignoring file '{fp}' due to extension rule '{ext}'.")
                continue

            # Check file size before full processing
            try:
                st_size = os.path.getsize(fp)
                if st_size > max_bytes:
                    skipped_policy_count += 1
                    logger.warning(f"[Policy Filter] Ignoring file '{fp}' ({st_size} bytes) exceeding max_file_size limit ({max_bytes} bytes).")
                    continue
            except OSError:
                pass

            meta = self.metadata_collector.collect(fp, include_hash=enable_hashing)
            if meta:
                scan_record = {
                    "usb_event_id": usb_event_id,
                    "file_name": meta["file_name"],
                    "full_path": meta["full_path"],
                    "extension": meta["extension"],
                    "file_size": meta["file_size"],
                    "sha256": meta["sha256"],
                    "is_hidden": meta["is_hidden"],
                    "created_at": meta["created_at"],
                    "modified_at": meta["modified_at"],
                }
                scanned_results.append(scan_record)

                # Auto-quarantine dangerous executable/script on USB if policy requires
                if auto_quarantine and ext in DANGEROUS_EXTENSIONS:
                    q_res = self.quarantine_manager.quarantine_file(
                        fp,
                        reason=f"Policy Auto-Quarantine: Dangerous extension {ext} detected on USB drive",
                        sha256=meta["sha256"]
                    )
                    if q_res:
                        quarantined_count += 1
                        logger.info(f"🛡️ [Auto Quarantine] Moved dangerous file '{fp}' to vault.")

            # Progress logging & Batch upload
            if len(scanned_results) >= self.batch_size:
                logger.info(f"⬆️ [Upload Queue] Batching {len(scanned_results)} scan results to backend...")
                res = self.api_client.send_usb_scans(scanned_results)
                if res is not None:
                    uploaded_total += len(scanned_results)
                scanned_results = []

            if idx % 50 == 0 or idx == len(file_paths):
                logger.info(f"📊 [Scan Progress] Processed {idx}/{len(file_paths)} files ({uploaded_total} uploaded, {skipped_policy_count} skipped by policy)...")

        # Flush remaining results in queue
        if scanned_results:
            logger.info(f"⬆️ [Upload Queue] Uploading final batch of {len(scanned_results)} scan results to backend...")
            res = self.api_client.send_usb_scans(scanned_results)
            if res is not None:
                uploaded_total += len(scanned_results)

        summary = {
            "scanned_count": len(file_paths),
            "uploaded_count": uploaded_total,
            "skipped_policy_count": skipped_policy_count,
            "quarantined_count": quarantined_count,
            "metrics": scanner.get_summary()
        }
        logger.info(
            f"✅ [Scan Complete] Successfully processed drive '{drive_path}'. "
            f"Scanned: {summary['scanned_count']}, Uploaded: {summary['uploaded_count']}, "
            f"Skipped by Policy: {summary['skipped_policy_count']}, Quarantined: {summary['quarantined_count']}."
        )
        return summary

    def _process_queue(self):
        while self._running:
            try:
                usb_event_id, drive_letter = self.scan_queue.get(timeout=1.0)
                self.process_scan_task(usb_event_id, drive_letter)
                self.scan_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"[USBScanPipelineWorker] Error processing queue task: {e}")
