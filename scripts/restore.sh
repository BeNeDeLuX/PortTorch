#!/usr/bin/env bash
#
# Restores a scripts/backup.sh archive into the current stack. This is
# destructive: the existing database contents and the existing
# screenshots/certs volumes are replaced, not merged.
#
#   scripts/restore.sh backups/porttorch-20260828-101500Z.tar.gz
#   scripts/restore.sh --yes <archive>     # skip the confirmation prompt
#
# The webserver is stopped for the duration and started again at the end,
# so nothing is writing to the database or the volumes mid-restore.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ASSUME_YES=0
ARCHIVE=""

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *) ARCHIVE="$1"; shift ;;
  esac
done

if [ -z "$ARCHIVE" ]; then
  echo "usage: scripts/restore.sh [--yes] <archive.tar.gz>" >&2
  exit 2
fi
if [ ! -f "$ARCHIVE" ]; then
  echo "error: no such archive: $ARCHIVE" >&2
  exit 1
fi

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

tar xzf "$ARCHIVE" -C "$STAGING"
for f in manifest.txt db.sql.gz data.tar.gz; do
  if [ ! -f "$STAGING/$f" ]; then
    echo "error: archive is missing $f - not a PortTorch backup?" >&2
    exit 1
  fi
done

echo "--- backup manifest ---"
cat "$STAGING/manifest.txt"
echo "-----------------------"

# A backup taken on a newer schema than the code being restored into will
# reference tables/columns this checkout's migrations don't know about.
# Warn rather than refuse: restoring into a newer checkout is fine and
# common (that's what migrations are for), it's only the other direction
# that's a problem, and the operator is better placed to judge it.
BACKUP_MIGRATION="$(sed -n 's/^schema_migration=//p' "$STAGING/manifest.txt")"
LOCAL_MIGRATION="$(ls server/migrations | sed 's/\.js$//' | sort | tail -1)"
if [ -n "$BACKUP_MIGRATION" ] && [ "$BACKUP_MIGRATION" != "unknown" ] && [ "$BACKUP_MIGRATION" \> "$LOCAL_MIGRATION" ]; then
  echo "WARNING: backup was taken at migration $BACKUP_MIGRATION, this checkout only has $LOCAL_MIGRATION."
  echo "         Restoring a newer schema into older code will not work correctly."
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  echo "This REPLACES the current database and the screenshots/certs volumes."
  printf "Type 'restore' to continue: "
  read -r answer
  if [ "$answer" != "restore" ]; then
    echo "aborted"
    exit 1
  fi
fi

WEB_CID="$(docker compose ps -aq webserver || true)"
if [ -z "$WEB_CID" ]; then
  echo "error: no 'webserver' container found - bring the stack up once first so its volumes exist" >&2
  exit 1
fi

echo "==> stopping webserver"
docker compose stop webserver >/dev/null

echo "==> starting postgres"
docker compose up -d postgres >/dev/null
# up -d returns as soon as the container is started, not when Postgres is
# ready to accept connections - the compose healthcheck is the thing that
# actually knows, so poll it rather than sleeping a guessed interval.
for _ in $(seq 1 60); do
  if docker compose exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker compose exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
  echo "error: postgres did not become ready" >&2
  exit 1
fi

echo "==> restoring database"
# The dump was written with --clean --if-exists, so it drops and recreates
# each object itself. ON_ERROR_STOP=1 means a partial restore fails loudly
# here instead of leaving a half-populated database that looks fine.
# psql --quiet only silences informational chatter, not result rows - and
# a --clean dump's own setval()/DROP output is hundreds of lines of noise
# that buries anything that actually matters. Errors still surface: they
# go to stderr, and ON_ERROR_STOP=1 makes the exit status non-zero.
gunzip -c "$STAGING/db.sql.gz" | docker compose exec -T postgres sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 --quiet' >/dev/null

echo "==> restoring /data volumes (screenshots, certs)"
# Clears the *contents* rather than the directories: /data/screenshots and
# /data/certs are each their own volume mounted at that path, so `rm -rf`
# on the directory itself fails with "Resource busy" (confirmed - it's what
# the first real run of this script did). The archive was written with
# `tar -C /data .`, so extracting it back over the now-empty mount points
# restores both volumes in place.
docker run --rm --volumes-from "$WEB_CID" -v "$STAGING:/backup:ro" alpine:3 sh -c \
  'find /data -mindepth 2 -delete 2>/dev/null; tar xzf /backup/data.tar.gz -C /data'

echo "==> starting webserver"
docker compose up -d >/dev/null

echo "==> restore complete"
echo "    Check it came up:  curl -sk https://localhost/healthz"
