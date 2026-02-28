#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
OUT_DIR="${1:-./backups}"
mkdir -p "$OUT_DIR"
STAMP=$(date +"%Y%m%d-%H%M%S")
OUT_FILE="$OUT_DIR/erpdb-$STAMP.dump"

pg_dump "$DATABASE_URL" -Fc -f "$OUT_FILE"
echo "Backup created: $OUT_FILE"
