#!/bin/bash
# Argus OSINT Database Backup Script
# Run via: ./scripts/backup.sh

set -euo pipefail
BACKUP_DIR="/var/backups/argus-osint"
DB_PATH="${DB_PATH:-/opt/argus-osint/data/argus.db}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/argus_${TIMESTAMP}.db"
RETAIN_DAYS=${RETAIN_DAYS:-30}

mkdir -p "$BACKUP_DIR"

if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "$BACKUP_FILE"
    echo "[$(date)] Backup created: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
    # Cleanup old backups
    find "$BACKUP_DIR" -name "argus_*.db" -mtime +$RETAIN_DAYS -delete
else
    echo "[$(date)] Database not found at $DB_PATH"
    exit 1
fi