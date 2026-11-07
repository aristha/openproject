#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
MODE="${1:---dry-run}"
IMAGE="${2:-}"
case "$MODE" in --dry-run|--execute) ;; *) echo "Usage: deploy.sh --dry-run|--execute ghcr.io/aristha/openproject@sha256:<digest>" >&2; exit 2 ;; esac
[[ "$IMAGE" =~ ^ghcr\.io/aristha/openproject@sha256:[a-f0-9]{64}$ ]] || { echo "Require immutable GHCR digest" >&2; exit 2; }

ROOT="${DEPLOY_ROOT:-/opt/openproject-pilot}"
HOST="${DEPLOY_HOST:-projects.betajapansoftware.com}"
URL="${DEPLOY_HEALTH_URL:-http://127.0.0.1:8080/health_check}"
BACKUP_HOOK="${DEPLOY_BACKUP_HOOK:-}"
LOCK="${DEPLOY_LOCK_FILE:-/tmp/openproject-portable-deploy.lock}"
OVERRIDE=compose.deploy.yaml

[[ "$HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || { echo "Invalid DEPLOY_HOST" >&2; exit 2; }
[[ "$URL" =~ ^https?://(127\.0\.0\.1|localhost)(:[0-9]+)?/[a-zA-Z0-9_./-]+$ ]] || { echo "Health endpoint must be localhost" >&2; exit 2; }
[[ -f "$ROOT/compose.yaml" ]] || { echo "Missing $ROOT/compose.yaml" >&2; exit 1; }
echo "Mode=$MODE Root=$ROOT Host=$HOST Image=$IMAGE"
if [[ "$MODE" == "--dry-run" ]]; then
 echo "DRY_RUN_OK: no containers, files or cloud resources changed"
 exit 0
fi
[[ "${DEPLOY_SCHEMA_APPROVED:-}" == NO_MIGRATIONS ]] || { echo "Schema review required: DEPLOY_SCHEMA_APPROVED=NO_MIGRATIONS" >&2; exit 1; }
[[ -n "$BACKUP_HOOK" && "$BACKUP_HOOK" == /* && -x "$BACKUP_HOOK" ]] || { echo "Executable absolute DEPLOY_BACKUP_HOOK required" >&2; exit 1; }
cd "$ROOT"
for cmd in flock docker curl; do command -v "$cmd" >/dev/null; done
exec 9>"$LOCK"
flock -n 9 || { echo "Another deploy is running" >&2; exit 1; }
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml exec -T db pg_isready -U openproject -d openproject >/dev/null
WEB_ID="$(docker compose -f compose.yaml ps -q web)"
[[ -n "$WEB_ID" ]] || { echo "Web not running" >&2; exit 1; }
"$BACKUP_HOOK"
echo "Backup hook passed"
docker pull "$IMAGE"
had_override=no
if [[ -f "$OVERRIDE" ]]; then cp -p "$OVERRIDE" "$OVERRIDE.previous"; had_override=yes; fi
rollback() {
  rc=$?
  trap - ERR
  echo "Deployment failed. Attempting image-only rollback; DB unchanged by script." >&2
  if [[ "$had_override" == yes ]]; then
    cp -p "$OVERRIDE.previous" "$OVERRIDE"
    docker compose -f compose.yaml -f "$OVERRIDE" up -d --no-deps web worker || true
  else
    rm -f "$OVERRIDE"
    docker compose -f compose.yaml up -d --no-deps web worker || true
  fi
  exit "$rc"
}
trap rollback ERR
cat > "$OVERRIDE" <<EOF
services:
  web:
    image: "$IMAGE"
  worker:
    image: "$IMAGE"
EOF
docker compose -f compose.yaml -f "$OVERRIDE" config --quiet
docker compose -f compose.yaml -f "$OVERRIDE" up -d --no-deps web worker
healthy=no
for n in $(seq 1 36); do
  # Rails may force HTTPS and redirect plain HTTP. Forwarded scheme mirrors
  # the trusted TLS proxy; require HTTP 200, not a 301/302 redirect.
  status="$(curl --silent --show-error --max-time 8 -o /dev/null -w '%{http_code}' -H "Host: $HOST" -H 'X-Forwarded-Proto: https' "$URL")" || status="000"
  if [[ "$status" == 200 ]]; then healthy=yes; break; fi
  sleep 10
done
[[ "$healthy" == yes ]] || { echo "Health check failed: $URL" >&2; false; }
for service in web worker; do
  id="$(docker compose -f compose.yaml -f "$OVERRIDE" ps -q "$service")"
  [[ -n "$id" && "$(docker inspect --format '{{.State.Running}}' "$id")" == true ]] || { echo "$service not running" >&2; false; }
done
trap - ERR
echo "DEPLOY_SUCCESS image=$IMAGE"
