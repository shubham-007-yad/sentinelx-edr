#!/usr/bin/env bash
# ===================================================================
# SentinelX EDR Automated PostgreSQL Backup Script
# Usage: ./scripts/backup_db.sh [output_directory]
# ===================================================================

set -e

BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DB_NAME="${POSTGRES_DB:-sentinelx}"
DB_USER="${POSTGRES_USER:-sentinel}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5433}"
BACKUP_FILE="${BACKUP_DIR}/sentinelx_backup_${TIMESTAMP}.dump"

mkdir -p "$BACKUP_DIR"

echo "[+] Starting PostgreSQL Backup for '${DB_NAME}' at $(date)..."
echo "[+] Destination: ${BACKUP_FILE}"

export PGPASSWORD="${POSTGRES_PASSWORD:-sentinel}"

pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -F c -b -v -f "$BACKUP_FILE" "$DB_NAME"

FILE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "[+] Backup successfully created (${FILE_SIZE}): ${BACKUP_FILE}"
