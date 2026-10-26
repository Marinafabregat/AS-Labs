#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not available. Enable Docker Desktop WSL integration or install Docker Engine." >&2
  exit 1
fi

COMPOSE=(docker compose -p vinsec-scan -f docker-compose.yml -f docker-compose.scan.yml)

mkdir -p zap/reports

cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Start from a clean stack so the throwaway SQLite DB is always freshly seeded,
# even if a previous scan was interrupted before its cleanup trap ran.
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true

"${COMPOSE[@]}" up -d --build --force-recreate --wait app

set +e
"${COMPOSE[@]}" --profile security run --rm --no-deps zap
status=$?
set -e

echo "ZAP reports written to: $PROJECT_DIR/zap/reports"
exit "$status"
