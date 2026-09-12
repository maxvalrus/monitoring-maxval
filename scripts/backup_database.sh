#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
backup_dir=${1:-"$project_dir/backups"}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
archive="$backup_dir/monitoring-maxval-$timestamp.dump"

umask 077
mkdir -p "$backup_dir"
cd "$project_dir"
docker compose exec -T db sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-acl' \
  > "$archive"
docker compose exec -T db pg_restore --list < "$archive" >/dev/null

echo "Backup created and verified: $archive"
