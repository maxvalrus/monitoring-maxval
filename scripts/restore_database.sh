#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ "$2" != "--confirm-replace-database" ]; then
  echo "Usage: $0 /path/to/backup.dump --confirm-replace-database" >&2
  exit 2
fi

archive=$1
if [ ! -f "$archive" ]; then
  echo "Backup file not found: $archive" >&2
  exit 2
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
docker compose exec -T db pg_restore --list < "$archive" >/dev/null
docker compose stop app
trap 'docker compose start app >/dev/null 2>&1 || true' EXIT
docker compose exec -T db sh -c \
  'dropdb --if-exists --force -U "$POSTGRES_USER" "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" "$POSTGRES_DB"'
docker compose exec -T db sh -c \
  'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --exit-on-error' \
  < "$archive"
docker compose start app
docker compose exec -T app alembic current
trap - EXIT

echo "Database restored and application started."
