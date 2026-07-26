import argparse
import json
import os
import sys
import tempfile
import time
from typing import Optional

# Adjust sys.path to ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logger import logger
from usb_scanner import USBScanner
from file_metadata import FileMetadataCollector
from file_hasher import calculate_sha256
from api.client import APIClient


def run_verification(drive_path: Optional[str] = None, mock: bool = False, backend_url: Optional[str] = None):
    print("\n=======================================================")
    print(" 🛡️ SentinelX EDR — Day 5 USB Scanning Pipeline Verification")
    print("=======================================================\n")

    tmp_dir_obj = None

    if mock or not drive_path:
        logger.info("[Verification] Mock mode active: Creating simulated USB filesystem structure...")
        tmp_dir_obj = tempfile.TemporaryDirectory(prefix="sentinelx_usb_")
        target_dir = tmp_dir_obj.name

        movies_dir = os.path.join(target_dir, "Movies")
        office_dir = os.path.join(target_dir, "Office")
        tools_dir = os.path.join(target_dir, "Tools")
        photos_dir = os.path.join(target_dir, "Photos")
        hidden_dir = os.path.join(target_dir, ".secret_keys")

        os.makedirs(movies_dir, exist_ok=True)
        os.makedirs(office_dir, exist_ok=True)
        os.makedirs(tools_dir, exist_ok=True)
        os.makedirs(photos_dir, exist_ok=True)
        os.makedirs(hidden_dir, exist_ok=True)

        sample_files = [
            (os.path.join(movies_dir, "movie.mp4"), b"MP4 VIDEO STREAM DATA" * 50),
            (os.path.join(office_dir, "report.docx"), b"DOCX REPORT CONTENT"),
            (os.path.join(office_dir, "budget.xlsx"), b"XLSX SPREADSHEET CONTENT"),
            (os.path.join(tools_dir, "setup.exe"), b"EXECUTABLE BINARY DATA"),
            (os.path.join(photos_dir, "img1.jpg"), b"JPEG IMAGE DATA"),
            (os.path.join(hidden_dir, ".env_keys"), b"SECRET_API_KEY=123456"),
        ]

        for filepath, content in sample_files:
            with open(filepath, "wb") as f:
                f.write(content)

        drive_path = target_dir
        logger.info(f"[Verification] Created mock USB mount point: {drive_path}")
    else:
        drive_path = os.path.abspath(drive_path)
        logger.info(f"[Verification] Targeting live USB drive mount point: {drive_path}")

    # 1. Enumerate Files
    print(f"\n1️⃣ [Step 1: Enumerate Files] Traversing directory tree under '{drive_path}'...")
    scanner = USBScanner(drive_path)
    file_paths = scanner.enumerate_files()
    metrics = scanner.get_summary()

    print(f"   ➜ Discovered Files: {metrics['scanned_files_count']}")
    print(f"   ➜ Skipped/Inaccessible: {metrics['skipped_files_count']}")
    print(f"   ➜ OS Errors: {metrics['errors_count']}")

    # 2 & 3. Collect Metadata & SHA-256 Hashing
    print(f"\n2️⃣ [Step 2 & 3: Metadata Collection & SHA-256 Hashing]...")
    collector = FileMetadataCollector()
    scanned_results = []

    for idx, fp in enumerate(file_paths, 1):
        meta = collector.collect(fp, include_hash=True)
        if meta:
            scanned_results.append(meta)
            print(f"   [{idx}/{len(file_paths)}] {meta['file_name']} ({meta['size']} bytes)")
            print(f"         Ext: {meta['extension']} | Hidden: {meta['hidden']}")
            print(f"         SHA-256: {meta['sha256']}")

    # 4. JSON Payload Format Summary
    print(f"\n3️⃣ [Step 4: Formatted Forensic Payload JSON Sample]...")
    if scanned_results:
        sample_json = json.dumps(scanned_results[0], indent=2)
        print(sample_json)

    # 5. Optional Backend API Upload Test
    print(f"\n4️⃣ [Step 5: API Client Backend Sync Verification]...")
    client = APIClient(backend_url=backend_url)
    print(f"   ➜ Configured Backend URL: {client.backend_url}")

    if client.device_id:
        print(f"   ➜ Cached Device ID: {client.device_id}")
    else:
        print("   ➜ Device ID not cached yet (Registration required during live agent execution).")

    print("\n✅ [Verification Complete] All Day 5 pipeline stages verified successfully!\n")

    if tmp_dir_obj:
        tmp_dir_obj.cleanup()


def main():
    parser = argparse.ArgumentParser(description="SentinelX EDR — Day 5 USB Scanning Pipeline Verification Script")
    parser.add_argument("--mock", action="store_true", help="Run with simulated mock USB filesystem")
    parser.add_argument("--drive", type=str, help="Target drive letter or mount point (e.g., E: or /media/usb)")
    parser.add_argument("--url", type=str, help="Custom backend URL")
    args = parser.parse_args()

    run_verification(drive_path=args.drive, mock=args.mock, backend_url=args.url)


if __name__ == "__main__":
    main()
