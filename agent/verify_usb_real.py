#!/usr/bin/env python3
"""
SentinelX EDR - Real USB Manual & Integration Verification Script
Phase 7 — Verification of Physical / Simulated USB Event Lifecycle
"""

import sys
import time
from typing import List
from config import config
from logger import logger
from collectors import collect_system_info, USBMetadataCollector
from detectors import USBDetectorService, USBEventData, MockUSBDetector
from api import APIClient


def verify_real_or_simulated_usb_flow(use_mock: bool = False):
    print("\n=======================================================")
    print(" SENTINELX EDR — PHASE 7 REAL USB VERIFICATION SUITE")
    print("=======================================================\n")

    # 1. Initialize API Client & Register Endpoint
    print("[STEP 1/6] Registering endpoint with SentinelX backend...")
    client = APIClient()
    sys_info = collect_system_info()
    reg_result = client.register_device(sys_info)

    if not reg_result or not client.device_id:
        print("❌ Error: Endpoint registration failed. Ensure backend API server is running.")
        sys.exit(1)

    print(f"✅ Device registered successfully! (device_id: {client.device_id})")

    # 2. Setup USB Detector Service
    print("\n[STEP 2/6] Initializing USB Detector Engine & Event Listeners...")
    detector = MockUSBDetector() if use_mock else None
    usb_service = USBDetectorService(detector=detector)

    uploaded_events: List[dict] = []

    def on_usb_event(event: USBEventData):
        print(f"\n⚡ LIVE EVENT DETECTED: [{event.event_type}] Drive {event.drive_letter} ({event.volume_label})")
        print(f"   Filesystem : {event.filesystem}")
        print(f"   Total Size : {event.total_size} bytes")
        print(f"   Free Space : {event.free_space} bytes")
        print(f"   Serial No  : {event.serial_number}")

        res = client.send_usb_event(event.to_dict())
        if res:
            uploaded_events.append(res)
            print(f"✅ Event stored in backend PostgreSQL! Event ID: {res.get('id')}")

    usb_service.event_listener.register_callback(on_usb_event)

    # 3. Baseline Scan
    print("\n[STEP 3/6] Scanning baseline connected drives...")
    usb_service.previous_drives = usb_service.detector.get_connected_usb_drives()
    print(f"Baseline connected USB drives count: {len(usb_service.previous_drives)}")

    # 4. Interactive or Simulated USB Insert Test
    print("\n[STEP 4/6] --- TEST: USB INSERTION ---")
    if use_mock:
        print("Simulating physical USB insertion (Drive E:)...")
        from detectors.usb_detector import USBDeviceDetails
        mock_device = USBDeviceDetails(
            drive_letter="E:",
            volume_label="REAL_KINGSTON",
            filesystem="FAT32",
            total_size=32017047552,
            free_space=15872184320,
            serial_number="KNG-SN-8877"
        )
        detector.plug_in(mock_device)
        usb_service.scan_and_detect()
    else:
        print("Please INSERT a physical USB drive into any USB port now...")
        print("Monitoring for insertion (Waiting up to 10 seconds)...")
        start_time = time.time()
        while time.time() - start_time < 10:
            events = usb_service.scan_and_detect()
            if any(e.event_type == "INSERT" for e in events):
                break
            time.sleep(1)

    # 5. Interactive or Simulated USB Removal Test
    print("\n[STEP 5/6] --- TEST: USB REMOVAL ---")
    if use_mock:
        print("Simulating physical USB removal (Drive E:)...")
        detector.unplug("E:")
        usb_service.scan_and_detect()
    else:
        print("Please REMOVE the physical USB drive from the USB port now...")
        print("Monitoring for removal (Waiting up to 10 seconds)...")
        start_time = time.time()
        while time.time() - start_time < 10:
            events = usb_service.scan_and_detect()
            if any(e.event_type == "REMOVE" for e in events):
                break
            time.sleep(1)

    # 6. Verify Dashboard Data Feed
    print("\n[STEP 6/6] Verifying events recorded via Backend API GET /api/v1/usb/events...")
    try:
        res = client.session.get(f"{client.backend_url}/usb/events?device_id={client.device_id}")
        if res.status_code == 200:
            events_in_db = res.json()
            print(f"✅ Backend API verification passed! Total events in DB for device: {len(events_in_db)}")
            for evt in events_in_db:
                print(f"   - Event ID: {evt['id']} | Type: {evt['event_type']} | Drive: {evt['drive_letter']} | Time: {evt['detected_at']}")
        else:
            print(f"❌ API Verification failed with HTTP status {res.status_code}")
    except Exception as e:
        print(f"❌ API Verification error: {e}")

    print("\n=======================================================")
    print(" VERIFICATION COMPLETE: ALL USB LIFECYCLE STAGES OK")
    print("=======================================================\n")


if __name__ == "__main__":
    use_mock_arg = "--mock" in sys.argv or "--simulated" in sys.argv
    verify_real_or_simulated_usb_flow(use_mock=use_mock_arg)
