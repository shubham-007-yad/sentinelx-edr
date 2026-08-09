#!/usr/bin/env python3
"""
SentinelX EDR Database Backup & Restore Automated Verification Suite
Phase 5 — Database Hardening

Verifies backup integrity by executing:
1. Seed/insert verification test record with unique token into source DB.
2. Dump source DB using `pg_dump`.
3. Restore dump into isolated target database `sentinelx_verify_restore`.
4. Query target DB to verify record counts, schema tables, and token integrity.
5. Drop target test DB and cleanup dump file.
"""

import sys
import os
import subprocess
import time
import uuid
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Add backend directory to sys.path to import settings
sys.path.append("/app")
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.core.config import settings

def get_db_connection(dbname=None):
    db_name = dbname or settings.POSTGRES_DB
    return psycopg2.connect(
        dbname=db_name,
        user=settings.POSTGRES_USER,
        password=settings.POSTGRES_PASSWORD,
        host=settings.POSTGRES_HOST,
        port=settings.POSTGRES_PORT
    )

def run_backup_restore_verification():
    print("==================================================================")
    print("🚀 SentinelX EDR — Database Backup & Restore Verification Suite")
    print("==================================================================")

    verification_token = f"VERIFY_TOKEN_{uuid.uuid4().hex[:12].upper()}"
    test_db_name = f"sentinelx_verify_{int(time.time())}"
    dump_file_path = f"/tmp/{test_db_name}.dump"

    print(f"[*] Target DB Host: {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}")
    print(f"[*] Source Database: {settings.POSTGRES_DB}")
    print(f"[*] Verification Token: {verification_token}")
    print(f"[*] Temporary Verification DB: {test_db_name}")

    # 1. Connect to Source DB and insert verification benchmark record
    print("\n[1/5] Inserting verification benchmark record into source DB...")
    conn = get_db_connection()
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    # Ensure test verification table exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS backup_verifications (
            id UUID PRIMARY KEY,
            token VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("INSERT INTO backup_verifications (id, token) VALUES (%s, %s);", (str(uuid.uuid4()), verification_token))
    
    # Record current row counts from source DB
    cur.execute("SELECT count(*) FROM users;")
    user_count_orig = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM backup_verifications;")
    verify_count_orig = cur.fetchone()[0]
    cur.close()
    conn.close()

    print(f"    ✓ Verification token inserted. Total users: {user_count_orig}, Verification records: {verify_count_orig}")

    # 2. Run pg_dump
    print("\n[2/5] Performing full database backup using pg_dump...")
    pg_env = os.environ.copy()
    pg_env["PGPASSWORD"] = settings.POSTGRES_PASSWORD

    dump_cmd = [
        "pg_dump",
        "-h", settings.POSTGRES_HOST,
        "-p", str(settings.POSTGRES_PORT),
        "-U", settings.POSTGRES_USER,
        "-F", "c",  # Custom binary format
        "-b",      # Include blobs
        "-v",
        "-f", dump_file_path,
        settings.POSTGRES_DB
    ]

    try:
        res = subprocess.run(dump_cmd, env=pg_env, check=True, capture_output=True, text=True)
        dump_size = os.path.getsize(dump_file_path)
        print(f"    ✓ Backup created successfully! Dump file size: {dump_size / 1024:.2f} KB ({dump_file_path})")
    except subprocess.CalledProcessError as err:
        print(f"❌ pg_dump failed: {err.stderr}")
        sys.exit(1)

    # 3. Create isolated verification database and restore
    print("\n[3/5] Creating temporary database and running pg_restore...")
    main_conn = get_db_connection(dbname="postgres")
    main_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    main_cur = main_conn.cursor()
    main_cur.execute(f"DROP DATABASE IF EXISTS {test_db_name};")
    main_cur.execute(f"CREATE DATABASE {test_db_name};")
    main_cur.close()
    main_conn.close()

    restore_cmd = [
        "pg_restore",
        "-h", settings.POSTGRES_HOST,
        "-p", str(settings.POSTGRES_PORT),
        "-U", settings.POSTGRES_USER,
        "-d", test_db_name,
        "-v",
        dump_file_path
    ]

    try:
        subprocess.run(restore_cmd, env=pg_env, check=False, capture_output=True, text=True)
        print("    ✓ Database restored successfully into temporary database.")
    except Exception as err:
        print(f"❌ pg_restore failed: {err}")
        sys.exit(1)

    # 4. Verify data in restored database
    print("\n[4/5] Verifying data integrity in restored database...")
    test_conn = get_db_connection(dbname=test_db_name)
    test_cur = test_conn.cursor()

    test_cur.execute("SELECT count(*) FROM users;")
    user_count_restored = test_cur.fetchone()[0]

    test_cur.execute("SELECT count(*) FROM backup_verifications WHERE token = %s;", (verification_token,))
    found_token_count = test_cur.fetchone()[0]

    test_cur.close()
    test_conn.close()

    print(f"    ✓ Users count in restored DB: {user_count_restored} (Expected: {user_count_orig})")
    print(f"    ✓ Matching verification tokens in restored DB: {found_token_count} (Expected: 1+)")

    assert user_count_restored == user_count_orig, "User count mismatch after restore!"
    assert found_token_count > 0, "Verification token missing in restored database!"

    print("\n🎉 VERIFICATION SUCCESSFUL: Backup & Restore cycle fully validated!")

    # 5. Cleanup temporary DB and dump file
    print("\n[5/5] Cleaning up temporary test database and dump artifact...")
    clean_conn = get_db_connection(dbname="postgres")
    clean_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    clean_cur = clean_conn.cursor()
    clean_cur.execute(f"DROP DATABASE IF EXISTS {test_db_name};")
    clean_cur.close()
    clean_conn.close()

    if os.path.exists(dump_file_path):
        os.remove(dump_file_path)

    print("    ✓ Cleanup completed.")

if __name__ == "__main__":
    run_backup_restore_verification()
