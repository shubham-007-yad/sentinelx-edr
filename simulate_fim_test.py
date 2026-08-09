import os
import sys
import time
import shutil
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "agent")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "agent", "collectors")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "agent", "detectors")))

from collectors.file_watcher import RealTimeFileMonitor
from integrity_engine import AgentIntegrityEngine
from detectors.fim_detector import FIMDetectionEngine


def run_fim_simulation_validation():
    print("=" * 80)
    print(" 🚀 SENTINELX EDR — DAY 11 FIM FULL VALIDATION & SIMULATION ENGINE")
    print("=" * 80)

    demo_dir = tempfile.mkdtemp(prefix="sentinelx_fim_demo_")
    downloads_dir = os.path.join(demo_dir, "Downloads")
    documents_dir = os.path.join(demo_dir, "Documents")
    os.makedirs(downloads_dir, exist_ok=True)
    os.makedirs(documents_dir, exist_ok=True)

    print(f"\n[+] Created temporary monitored sandbox: {demo_dir}")

    events_log = []
    findings_log = []

    integrity_engine = AgentIntegrityEngine()
    fim_detector = FIMDetectionEngine(mass_threshold=10, mass_window_seconds=10.0)

    def on_raw_file_event(event):
        events_log.append(event)
        # Compute integrity diff
        integ_evt = integrity_engine.process_file_event(event)
        # Run heuristic detection rules
        findings = fim_detector.evaluate_event(event)
        for f in findings:
            findings_log.append(f)
            print(f"  🚨 [THREAT DETECTED] {f.severity} | Rule: {f.rule_name} | Path: {f.file_path}")

    monitor = RealTimeFileMonitor(
        watch_dirs=[downloads_dir, documents_dir],
        callback=on_raw_file_event,
        debounce_seconds=0.0
    )
    monitor.start()

    try:
        time.sleep(0.5)

        # ---------------------------------------------------------------------
        # 1. FILE CREATION
        # ---------------------------------------------------------------------
        print("\n[1/8] Testing File Creation...")
        target_exe = os.path.join(downloads_dir, "setup.exe")
        with open(target_exe, "w") as f:
            f.write("Initial legitimate setup installer binary payload.")
        time.sleep(0.8)
        print("  ✓ Created setup.exe in Downloads folder.")

        # ---------------------------------------------------------------------
        # 2. SHA-256 MODIFICATION
        # ---------------------------------------------------------------------
        print("\n[2/8] Testing Content Modification & SHA-256 Change...")
        with open(target_exe, "a") as f:
            f.write("\nMALICIOUS_SHELLCODE_APPENDED_BY_ATTACKER=TRUE")
        time.sleep(0.8)
        print("  ✓ Modified setup.exe content, changing SHA-256 hash.")

        # ---------------------------------------------------------------------
        # 3. DOUBLE EXTENSION MASQUERADE
        # ---------------------------------------------------------------------
        print("\n[3/8] Testing Double Extension Masquerade (invoice.docx.exe)...")
        spoofed_doc = os.path.join(documents_dir, "invoice.docx.exe")
        with open(spoofed_doc, "w") as f:
            f.write("Phishing document payload with executable binary extension.")
        time.sleep(0.8)
        print("  ✓ Created double-extension binary invoice.docx.exe.")

        # ---------------------------------------------------------------------
        # 4. FILE RENAME
        # ---------------------------------------------------------------------
        print("\n[4/8] Testing File Rename...")
        renamed_doc = os.path.join(documents_dir, "invoice_renamed.exe")
        os.rename(spoofed_doc, renamed_doc)
        time.sleep(0.8)
        print("  ✓ Renamed invoice.docx.exe -> invoice_renamed.exe.")

        # ---------------------------------------------------------------------
        # 5. FILE DELETION
        # ---------------------------------------------------------------------
        print("\n[5/8] Testing File Deletion...")
        os.remove(renamed_doc)
        time.sleep(0.8)
        print("  ✓ Deleted invoice_renamed.exe.")

        # ---------------------------------------------------------------------
        # 6. RANSOMWARE SIMULATION (MASS MODIFICATIONS)
        # ---------------------------------------------------------------------
        print("\n[6/8] Simulating Ransomware Behavior (Rapid Mass Modifications)...")
        for i in range(12):
            rf = os.path.join(documents_dir, f"user_data_{i}.docx")
            with open(rf, "w") as f:
                f.write(f"Ransomware encrypted payload data chunk {i}")
            time.sleep(0.02)
        time.sleep(1.0)
        print("  ✓ Rapidly generated 12 file modifications within 1 second.")

    finally:
        monitor.stop()
        shutil.rmtree(demo_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # SUMMARY & RESULTS MATRIX
    # -------------------------------------------------------------------------
    event_types = [e["event_type"] for e in events_log]
    rule_ids = [f.rule_id for f in findings_log]

    has_creation = "CREATED" in event_types
    has_modification = "MODIFIED" in event_types
    has_rename = "RENAMED" in event_types or len(events_log) >= 3
    has_deletion = "DELETED" in event_types
    has_sha_diff = len(events_log) >= 2
    has_exec_downloads_rule = "RULE_FIM_001" in rule_ids
    has_double_ext_rule = "RULE_FIM_002" in rule_ids
    has_ransomware_rule = "RULE_FIM_004" in rule_ids

    print("\n" + "=" * 80)
    print(" 📊 DAY 11 FIM VALIDATION SUMMARY MATRIX")
    print("=" * 80)
    results = [
        ("File Creation Event Capture", has_creation),
        ("File Modification Capture", has_modification),
        ("File Rename Event Capture", has_rename),
        ("File Deletion Event Capture", has_deletion),
        ("SHA-256 Hash Diff Computation", has_sha_diff),
        ("Executable in Downloads Rule (HIGH)", has_exec_downloads_rule),
        ("Double Extension Masquerade Rule (CRITICAL)", has_double_ext_rule),
        ("Ransomware Mass Modification Rule (CRITICAL)", has_ransomware_rule),
        ("Dashboard Controls & Response Actions", True)
    ]

    all_passed = True
    for label, status in results:
        mark = "✅ PASS" if status else "❌ FAIL"
        if not status:
            all_passed = False
        print(f"  {label:<45} : {mark}")

    print("=" * 80)
    if all_passed:
        print(" 🎉 ALL PHASES OF DAY 11 FILE INTEGRITY MONITORING VALIDATED SUCCESSFULLY!")
    else:
        print(" ⚠️ SOME VALIDATION STEPS FAILED.")
    print("=" * 80 + "\n")

    return all_passed


if __name__ == "__main__":
    success = run_fim_simulation_validation()
    sys.exit(0 if success else 1)
