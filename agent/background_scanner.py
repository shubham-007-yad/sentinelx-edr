import os
import queue
import threading
import time
from typing import Optional, List, Dict, Any
from logger import logger
from usb_scanner import USBScanner
from file_metadata import FileMetadataCollector
from api.client import APIClient


class USBScanPipelineWorker:
    """
    Automated Background USB Scan Pipeline Worker.
    Asynchronously handles file enumeration, metadata collection, SHA-256 hashing,
    progress logging, and batch uploads to the backend when a USB INSERT event occurs.
    """

    def __init__(self, api_client: APIClient, batch_size: int = 50):
        self.api_client = api_client
        self.batch_size = batch_size
        self.metadata_collector = FileMetadataCollector()
        self.scan_queue: queue.Queue = queue.Queue()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

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
        """Pushes a USB event scan task to the background queue."""
        logger.info(f"[USBScanPipelineWorker] Enqueueing automated scan task for event '{usb_event_id}' on drive '{drive_letter}'.")
        self.scan_queue.put((usb_event_id, drive_letter))

    def process_scan_task(self, usb_event_id: str, drive_letter: str) -> Dict[str, Any]:
        """
        Executes complete scan pipeline for a single USB event synchronously:
        Enumerate Files -> Collect Metadata & SHA-256 -> Batch Upload to Backend.
        """
        drive_path = os.path.abspath(drive_letter.rstrip('\\') + '\\') if os.name == 'nt' else drive_letter
        if not os.path.exists(drive_path):
            logger.error(f"[USBScanPipelineWorker] Target drive path does not exist: {drive_path}")
            return {"scanned_count": 0, "uploaded_count": 0, "errors": 1}

        logger.info(f"🔍 [Automated Scan Pipeline] Starting file scan on drive '{drive_path}' for USB event ID: {usb_event_id}")

        # 1. Enumerate files
        scanner = USBScanner(drive_path)
        file_paths = scanner.enumerate_files()
        logger.info(f"📂 [Enumeration Complete] Discovered {len(file_paths)} files on {drive_path}.")

        scanned_results: List[Dict[str, Any]] = []
        uploaded_total = 0

        # 2 & 3. Collect Metadata + SHA-256 Hashing
        for idx, fp in enumerate(file_paths, 1):
            meta = self.metadata_collector.collect(fp, include_hash=True)
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

            # Progress logging & Batch upload
            if len(scanned_results) >= self.batch_size:
                logger.info(f"⬆️ [Upload Queue] Batching {len(scanned_results)} scan results to backend...")
                res = self.api_client.send_usb_scans(scanned_results)
                if res is not None:
                    uploaded_total += len(scanned_results)
                scanned_results = []

            if idx % 50 == 0 or idx == len(file_paths):
                logger.info(f"📊 [Scan Progress] Processed {idx}/{len(file_paths)} files ({uploaded_total} uploaded)...")

        # Flush remaining results in queue
        if scanned_results:
            logger.info(f"⬆️ [Upload Queue] Uploading final batch of {len(scanned_results)} scan results to backend...")
            res = self.api_client.send_usb_scans(scanned_results)
            if res is not None:
                uploaded_total += len(scanned_results)

        summary = {
            "scanned_count": len(file_paths),
            "uploaded_count": uploaded_total,
            "metrics": scanner.get_summary()
        }
        logger.info(f"✅ [Scan Complete] Successfully processed drive '{drive_path}'. Scanned: {summary['scanned_count']}, Uploaded: {summary['uploaded_count']}.")
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
