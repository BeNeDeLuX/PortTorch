#!/usr/bin/env bash
#
# Updates the webserver container to the newest published image, without
# touching the running one until the new image is actually on disk.
#
# A plain `docker compose pull && docker compose up -d` is what the README
# always said to run, and it has two weaknesses this closes, both seen in
# practice: a registry timeout half-way through a pull fails the whole
# update (Docker Hub did this on two deploys running), and a failed pull
# followed by `up -d` quietly restarts the *old* image while looking like
# an update.
#
# So: the pull is retried with a growing pause; if Docker Hub keeps
# failing, the identical image is fetched from GitHub's registry instead
# (published by the same workflow) and tagged as the image compose
# expects; and the container is only recreated once one of those
# succeeded. Afterwards it waits for /healthz and prints the version the
# webserver reports, so "did it work" has an answer.
#
#   scripts/update-webserver.sh              # newest :latest
#   scripts/update-webserver.sh 0.57.0       # a specific published version
#
# Environment:
#   PULL_ATTEMPTS   tries per registry (default 4)
#   MIRROR_IMAGE    fallback image repository (default ghcr.io/benedelux/porttorch-server,
#                   empty to disable the fallback)
#   HEALTH_URL      what to poll after the restart (default https://localhost/healthz)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TAG="${1:-latest}"
ATTEMPTS="${PULL_ATTEMPTS:-4}"
MIRROR="${MIRROR_IMAGE-ghcr.io/benedelux/porttorch-server}"
HEALTH_URL="${HEALTH_URL:-https://localhost/healthz}"

log() { printf '[update-webserver] %s\n' "$*"; }
die() { printf '[update-webserver] ERROR: %s\n' "$*" >&2; exit 1; }

# The image compose runs, e.g. benedelux/porttorch-server:latest - read
# from the compose file rather than repeated here, so the two cannot drift.
COMPOSE_IMAGE="$(docker compose config 2>/dev/null | awk '/^  webserver:$/ { inside = 1; next } inside && /^  [^ ]/ { exit } inside && /^    image: / { print $2; exit }')"
[ -n "$COMPOSE_IMAGE" ] || die "could not read the webserver image from docker-compose.yml"
REPO="${COMPOSE_IMAGE%:*}"
WANT="$REPO:$TAG"

image_version() {
  docker run --rm --entrypoint sh "$1" -c "node -p \"require('./package.json').version\"" 2>/dev/null || echo "?"
}

pull_with_retries() {
  local image="$1" i
  for i in $(seq 1 "$ATTEMPTS"); do
    if docker pull -q "$image" >/dev/null 2>&1; then
      return 0
    fi
    if [ "$i" -lt "$ATTEMPTS" ]; then
      log "pulling $image failed (attempt $i of $ATTEMPTS), retrying in $((i * 15))s"
      sleep $((i * 15))
    fi
  done
  return 1
}

# Every deploy leaves the previous webserver image behind, untagged - on
# one host ten of them held 4 GB on a disk with 7 GB free. Once the new
# image is serving, the old ones go, except the one it replaced, kept so a
# bad release can be rolled back without a download.
#
# Only images built from this repository are touched: they carry the
# org.opencontainers.image.source label server/Dockerfile sets. Nothing
# else on the host - other projects' images, base images, build cache - is
# this script's to delete. An image a container still uses is skipped
# (docker refuses to remove it anyway). KEEP_OLD_IMAGES=1 turns it off.
IMAGE_SOURCE_LABEL="org.opencontainers.image.source=https://github.com/BeNeDeLuX/PortTorch"

prune_old_images() {
  [ "${KEEP_OLD_IMAGES:-0}" = "1" ] && return 0
  local in_use id freed=0 removed=0 size
  in_use="$(docker ps -aq | xargs -r docker inspect --format '{{.Image}}' 2>/dev/null | sort -u)"
  # -a: Docker 29 leaves untagged images out of a filtered listing
  # without it, and untagged is exactly what an old deploy leaves.
  for id in $(docker images -a -q --no-trunc --filter "label=$IMAGE_SOURCE_LABEL" | sort -u); do
    [ "$id" = "$AFTER" ] && continue
    [ -n "$BEFORE" ] && [ "$id" = "$BEFORE" ] && continue
    printf '%s\n' "$in_use" | grep -qx "$id" && continue
    size="$(docker image inspect --format '{{.Size}}' "$id" 2>/dev/null || echo 0)"
    if docker rmi "$id" >/dev/null 2>&1; then
      removed=$((removed + 1))
      freed=$((freed + size))
    fi
  done
  if [ "$removed" -gt 0 ]; then
    log "removed $removed old webserver image(s), about $((freed / 1024 / 1024)) MB (kept the previous one for rollback)"
  fi
}

BEFORE="$(docker image inspect --format '{{.Id}}' "$COMPOSE_IMAGE" 2>/dev/null || true)"

if pull_with_retries "$WANT"; then
  log "pulled $WANT"
elif [ -n "$MIRROR" ] && pull_with_retries "$MIRROR:$TAG"; then
  log "Docker Hub kept failing - pulled $MIRROR:$TAG instead"
  docker tag "$MIRROR:$TAG" "$WANT"
else
  die "could not pull $WANT${MIRROR:+ or $MIRROR:$TAG} - the running webserver was left untouched"
fi

# A specific version is run as the image compose expects, so `up -d`
# below starts exactly that and nothing else.
if [ "$WANT" != "$COMPOSE_IMAGE" ]; then
  docker tag "$WANT" "$COMPOSE_IMAGE"
fi

AFTER="$(docker image inspect --format '{{.Id}}' "$COMPOSE_IMAGE")"
NEW_VERSION="$(image_version "$COMPOSE_IMAGE")"
if [ "$BEFORE" = "$AFTER" ]; then
  log "already on the newest image ($NEW_VERSION) - recreating anyway is not needed"
else
  log "new image: version $NEW_VERSION"
fi

docker compose up -d webserver

# Healthy means the process is up and can reach its database - the same
# check a load balancer would use. Migrations run before the server
# listens, so a slow first boot after an upgrade is expected.
for _ in $(seq 1 60); do
  if body="$(curl -sk --max-time 3 "$HEALTH_URL")" && printf '%s' "$body" | grep -q '"status":"ok"'; then
    # The version the running process reports, not the one in the image -
    # the proof that the new image is the one actually serving. A healthy
    # answer from any other version means the old process has not been
    # replaced yet, so keep waiting.
    running="$(printf '%s' "$body" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
    if [ "$NEW_VERSION" = "?" ] || [ "$running" = "$NEW_VERSION" ]; then
      log "webserver is healthy, running version ${running:-$NEW_VERSION}"
      prune_old_images
      exit 0
    fi
  fi
  sleep 2
done
die "webserver did not report healthy at $HEALTH_URL within 2 minutes - check 'docker compose logs webserver'"
