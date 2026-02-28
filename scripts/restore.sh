#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
DUMP_FILE="${1:?Usage: ./scripts/restore.sh <dump-file>}"

pg_restore --clean --if-exists --no-owner --no-privileges -d "$DATABASE_URL" "$DUMP_FILE"
echo "Restore completed from: $DUMP_FILE"
