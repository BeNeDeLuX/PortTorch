#!/usr/bin/env bash
#
# Backs up everything that can't be rebuilt from the git checkout: the
# Postgres database (hosts, observations, findings, triage decisions,
# users, audit log) and the webserver's own /data volumes (screenshots,
# TLS certs). Everything else - images, migrations, config - comes back
# from `docker compose up` and .env.
#
# Runs pg_dump *inside* the postgres container and reads the volumes via
# --volumes-from the webserver container, so it needs no local psql, no
# local tar over a bind mount, and - importantly - never has to guess a
# volume name: whatever the webserver actually has mounted at /data is
# what gets archived, even if the compose project was renamed.
#
#   scripts/backup.sh                  # -> backups/porttorch-<ts>.tar.gz
#   scripts/backup.sh -o /mnt/nas      # write somewhere else
#   scripts/backup.sh --keep 7         # delete all but the newest 7 in -o
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="$REPO_ROOT/backups"
KEEP=""

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output) OUT_DIR="$2"; shift 2 ;;
    --keep) KEEP="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! docker compose version >/dev/null 2>&1; then
  echo "error: 'docker compose' is not available" >&2
  exit 1
fi

# The webserver container is how we reach the certs/screenshots volumes.
# It only has to *exist* (--volumes-from works on a stopped container),
# so a backup taken while the stack is down still works.
WEB_CID="$(docker compose ps -aq webserver || true)"
if [ -z "$WEB_CID" ]; then
  echo "error: no 'webserver' container found - run this from a deployed stack" >&2
  exit 1
fi

if [ -z "$(docker compose ps -q postgres || true)" ]; then
  echo "error: the 'postgres' container is not running - start it first (docker compose up -d postgres)" >&2
  exit 1
fi

TS="$(date -u +%Y%m%d-%H%M%SZ)"
ARCHIVE="$OUT_DIR/porttorch-$TS.tar.gz"
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$OUT_DIR"

echo "==> dumping database"
# Credentials come from the container's own environment rather than from
# parsing .env here, so this can't drift from what the database actually
# runs with. --clean --if-exists makes the dump replayable into a database
# that already has a schema, which is what restore.sh relies on.
docker compose exec -T postgres sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' \
  | gzip -9 > "$STAGING/db.sql.gz"

if [ ! -s "$STAGING/db.sql.gz" ]; then
  echo "error: database dump is empty - aborting rather than writing a useless backup" >&2
  exit 1
fi

echo "==> archiving /data volumes (screenshots, certs)"
docker run --rm --volumes-from "$WEB_CID" -v "$STAGING:/backup" alpine:3 sh -c \
  'tar czf /backup/data.tar.gz -C /data . && chown '"$(id -u):$(id -g)"' /backup/data.tar.gz'

{
  echo "created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "checkout_version=$(grep -m1 '"version"' server/package.json | sed 's/.*: *"\(.*\)".*/\1/')"
  echo "webserver_image=$(docker inspect --format '{{.Config.Image}}' "$WEB_CID" 2>/dev/null || echo unknown)"
  echo "git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  # The schema version of the dump itself, read from node-pg-migrate's own
  # bookkeeping table rather than from `ls server/migrations` - the running
  # container's schema is what got dumped, and it can legitimately differ
  # from whatever the checkout happens to have on disk. restore.sh compares
  # this against the local migrations directory.
  echo "schema_migration=$(docker compose exec -T postgres sh -c \
    'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "select name from pgmigrations order by id desc limit 1"' \
    2>/dev/null | tr -d '\r' || echo unknown)"
} > "$STAGING/manifest.txt"

tar czf "$ARCHIVE" -C "$STAGING" manifest.txt db.sql.gz data.tar.gz
# The archive contains the TLS private key and every password hash in the
# database - not world-readable.
chmod 600 "$ARCHIVE"

echo "==> wrote $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

if [ -n "$KEEP" ]; then
  # shellcheck disable=SC2012
  ls -1t "$OUT_DIR"/porttorch-*.tar.gz 2>/dev/null | tail -n "+$((KEEP + 1))" | while read -r old; do
    echo "==> pruning $old"
    rm -f "$old"
  done
fi
