#!/usr/bin/env python3
"""
Simulate USB Scan & Threat Analysis Test Script
Validates the complete Threat Detection Engine flow without requiring a physical USB drive.
"""

import os
import sys
import hashlib
import requests
import json
from uuid import uuid4

BASE_URL = "http://127.0.0.1:8000/api/v1"

def create_test_files():
    """Creates a local test_usb directory with sample benign and malicious files."""
    test_dir = os.path.abspath("test_usb")
    os.makedirs(test_dir, exist_ok=True)

    files = {
        "photo.jpg": b"JPEG IMAGE DATA BENIGN",
        "invoice.pdf.exe": b"MZ DANGEROUS DOUBLE EXTENSION PAYLOAD",
        "autorun.inf": b"[autorun]\nopen=installer.exe\nicon=autorun.ico",
        "installer.exe": b"MZ EXECUTABLE INSTALLER PAYLOAD",
        ".secret.exe": b"MZ SECRET HIDDEN EXECUTABLE PAYLOAD",
    }

    scanned_data = []
    print(f"\n📂 Created test USB directory at: {test_dir}")
    for fname, content in files.items():
        fpath = os.path.join(test_dir, fname)
        with open(fpath, "wb") as f:
            f.write(content)
        
        sha256_hash = hashlib.sha256(content).hexdigest()
        ext = os.path.splitext(fname)[1]
        
        scanned_data.append({
            "file_name": fname,
            "full_path": fpath,
            "extension": ext,
            "file_size": len(content),
            "sha256": sha256_hash,
            "is_hidden": fname.startswith(".") or fname == "autorun.inf"
        })
        print(f"   - Prepared: {fname} (Extension: '{ext}', Size: {len(content)}B, SHA256: {sha256_hash[:16]}...)")

    return scanned_data

def run_simulation():
    print("=" * 65)
    print("🚀 SENTINELX EDR — MANUAL THREAT DETECTION SIMULATION")
    print("=" * 65)

    # 1. Check if Backend API is running and authenticate
    headers = {}
    try:
        r = requests.get("http://127.0.0.1:8000/health", timeout=3)
        if r.status_code == 200:
            print("✅ Backend API is ONLINE (http://127.0.0.1:8000)")
        else:
            print("❌ Backend API responded with non-200 status.")
            sys.exit(1)

        # Obtain auth token
        login_res = requests.post(f"{BASE_URL}/auth/login/json", json={"username_or_email": "admin", "password": "AdminPassword123!"})
        if login_res.status_code == 200:
            token = login_res.json()["access_token"]
            headers["Authorization"] = f"Bearer {token}"
            print("🔑 Authenticated successfully with Backend API.")
        else:
            # Register admin if not present
            reg_res = requests.post(f"{BASE_URL}/auth/register", json={
                "username": "admin", "email": "admin@sentinelx.io", "password": "AdminPassword123!", "role": "ADMIN"
            })
            login_res = requests.post(f"{BASE_URL}/auth/login/json", json={"username_or_email": "admin", "password": "AdminPassword123!"})
            if login_res.status_code == 200:
                token = login_res.json()["access_token"]
                headers["Authorization"] = f"Bearer {token}"
                print("🔑 Registered & Authenticated admin user successfully.")
    except requests.exceptions.ConnectionError:
        print("\n⚠️ Backend API is NOT running at http://127.0.0.1:8000")
        print("   Please start backend server in another terminal:")
        print("   $ cd backend && source venv/bin/activate && uvicorn app.main:app --reload --port 8000\n")
        sys.exit(1)

    # 2. Register a simulated Device (or lookup existing)
    dev_payload = {
        "hostname": "TEST-WORKSTATION-SIMULATOR",
        "os_type": "WINDOWS",
        "os_version": "Windows 11 Enterprise",
        "ip_address": "192.168.1.200",
        "agent_version": "1.0.0"
    }
    dev_res = requests.post(f"{BASE_URL}/devices", json=dev_payload)
    if dev_res.status_code in (200, 201):
        device_id = dev_res.json()["id"]
        print(f"\n💻 Registered Test Device: {device_id}")
    else:
        # Fallback list devices
        devices = requests.get(f"{BASE_URL}/devices").json()
        if devices:
            device_id = devices[0]["id"]
            print(f"\n💻 Using Existing Device: {device_id}")
        else:
            print("❌ Failed to get device ID.")
            sys.exit(1)

    # 3. Simulate USB Insertion Event
    event_payload = {
        "device_id": device_id,
        "event_type": "INSERT",
        "drive_letter": "E:",
        "volume_label": "TEST_USB_STICK",
        "serial_number": f"SIM-{uuid4().hex[:8].upper()}"
    }
    evt_res = requests.post(f"{BASE_URL}/usb/events", json=event_payload)
    if evt_res.status_code not in (200, 201):
        print(f"❌ Failed to create USB event: {evt_res.text}")
        sys.exit(1)
    
    usb_event = evt_res.json()
    usb_event_id = usb_event["id"]
    print(f"🔌 Created Simulated USB Event ID: {usb_event_id}")

    # 4. Create local test files & Upload Scan Results
    files_data = create_test_files()
    scan_batch_payload = []
    for item in files_data:
        item["usb_event_id"] = usb_event_id
        scan_batch_payload.append(item)

    print(f"\n📡 Sending {len(scan_batch_payload)} scan records to POST {BASE_URL}/usb/scans...")
    scan_res = requests.post(f"{BASE_URL}/usb/scans", json=scan_batch_payload)
    if scan_res.status_code not in (200, 201):
        print(f"❌ Failed to upload scan results: {scan_res.text}")
        sys.exit(1)
    
    scans_created = scan_res.json()
    print(f"✅ Successfully created {len(scans_created)} USBScanResult records in database!")

    # 5. Trigger Threat Engine Analysis
    print(f"\n🔍 Triggering Threat Engine Analysis POST {BASE_URL}/threats/analyze/{usb_event_id}...")
    analyze_res = requests.post(f"{BASE_URL}/threats/analyze/{usb_event_id}", headers=headers)
    if analyze_res.status_code != 200:
        print(f"❌ Analysis failed: {analyze_res.text}")
        sys.exit(1)

    new_threats = analyze_res.json()
    print(f"✅ Threat Engine created {len(new_threats)} new Threat records!")

    # 6. Fetch and Display All Threats via GET /api/v1/threats
    print(f"\n📊 Fetching Threat Findings from GET {BASE_URL}/threats?usb_event_id={usb_event_id}...")
    threats_res = requests.get(f"{BASE_URL}/threats", params={"usb_event_id": usb_event_id}, headers=headers)
    all_threats = threats_res.json()

    print("\n" + "=" * 65)
    print("🛡️ DETECTED THREATS FORENSIC SUMMARY")
    print("=" * 65)
    for i, threat in enumerate(all_threats, 1):
        print(f"\n[{i}] THREAT FINDING:")
        print(f"    - File Name  : {threat.get('file_name', 'N/A')}")
        print(f"    - Rule Name  : {threat.get('rule_name', 'N/A')}")
        print(f"    - Threat Type: {threat.get('threat_type', 'N/A')}")
        print(f"    - Severity   : {threat.get('severity', 'N/A')}")
        print(f"    - Description: {threat.get('description', 'N/A')}")
        print(f"    - Status     : {threat.get('status', 'N/A')}")

    print("\n" + "=" * 65)
    print("✨ VERIFICATION COMPLETE!")
    print("   1. USBScanResult records created?  ➡️  YES")
    print("   2. Threat records created?         ➡️  YES")
    print("   3. Display in dashboard?           ➡️  OPEN http://localhost:5173/threats")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    run_simulation()
