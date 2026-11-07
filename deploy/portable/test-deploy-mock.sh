#!/usr/bin/env bash
# CI-only test: all Docker, curl and backup operations below are fakes.
set -Eeuo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/app"
printf 'services: {}\n' > "$TEST_ROOT/app/compose.yaml"
cat > "$TEST_ROOT/bin/docker" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'docker %s\n' "$*" >> "$MOCK_LOG"
if [[ "$1" == pull ]]; then exit 0; fi
if [[ "$1" == inspect ]]; then printf 'true\n'; exit 0; fi
if [[ "$1" != compose ]]; then exit 2; fi
args=" $* "
if [[ "$args" == *" config --quiet"* && "$args" == *" -f compose.deploy.yaml "* && "${MOCK_FAIL_CONFIG:-0}" == 1 ]]; then
  exit 8
fi
if [[ "$args" == *" ps -q web"* ]]; then printf 'web-id\n'; fi
if [[ "$args" == *" ps -q worker"* ]]; then printf 'worker-id\n'; fi
exit 0
SH
cat > "$TEST_ROOT/bin/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'curl %s\n' "$*" >> "$MOCK_LOG"
if [[ "${MOCK_HEALTH_HTTP:-200}" != 200 ]]; then
  printf '%s' "$MOCK_HEALTH_HTTP"
else
  printf '200'
fi
exit 0
SH
cat > "$TEST_ROOT/backup" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'backup\n' >> "$MOCK_LOG"
if [[ "${MOCK_FAIL_BACKUP:-0}" == 1 ]]; then exit 7; fi
SH
cat > "$TEST_ROOT/bin/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod 700 "$TEST_ROOT/bin/docker" "$TEST_ROOT/bin/curl" "$TEST_ROOT/bin/sleep" "$TEST_ROOT/backup"
export PATH="$TEST_ROOT/bin:$PATH"
export DEPLOY_ROOT="$TEST_ROOT/app"
export DEPLOY_LOCK_FILE="$TEST_ROOT/lock"
export DEPLOY_BACKUP_HOOK="$TEST_ROOT/backup"
export DEPLOY_SCHEMA_APPROVED=NO_MIGRATIONS
export MOCK_LOG="$TEST_ROOT/log"
IMAGE="ghcr.io/aristha/openproject@sha256:$(printf 'a%.0s' {1..64})"
SCRIPT="$PROJECT_ROOT/deploy/portable/deploy.sh"

die() { echo "FAIL: $*" >&2; exit 1; }
: > "$MOCK_LOG"
# Missing schema approval must fail before Docker or backup operations.
if DEPLOY_SCHEMA_APPROVED="" bash "$SCRIPT" --execute "$IMAGE"; then
  die "Missing schema approval accepted"
fi
[[ ! -s "$MOCK_LOG" ]] || die "Modified containers before schema approval"

# A failing backup must prevent image pull and config changes.
if MOCK_FAIL_BACKUP=1 bash "$SCRIPT" --execute "$IMAGE"; then
  die "Failing backup accepted"
fi
! grep -q '^docker pull ' "$MOCK_LOG" || die "Pulled image before backup passed"
[[ ! -f "$DEPLOY_ROOT/compose.deploy.yaml" ]] || die "Override written on failed backup"

# Failure validating the new overlay should restore an existing override.
printf 'services:\n  web:\n    image: old\n  worker:\n    image: old\n' > "$DEPLOY_ROOT/compose.deploy.yaml"
cp "$DEPLOY_ROOT/compose.deploy.yaml" "$TEST_ROOT/old"
: > "$MOCK_LOG"
if MOCK_FAIL_CONFIG=1 bash "$SCRIPT" --execute "$IMAGE"; then
  die "Failed configuration accepted"
fi
cmp "$DEPLOY_ROOT/compose.deploy.yaml" "$TEST_ROOT/old" ||
  die "Rollback failed to restore existing override"
grep -q '^docker compose .*up -d --no-deps web worker' "$MOCK_LOG" ||
  die "Rollback did not recreate web and worker"

# Failure to validate new overlay with no previous override must remove it.
rm -f "$DEPLOY_ROOT/compose.deploy.yaml"
: > "$MOCK_LOG"
if MOCK_FAIL_CONFIG=1 bash "$SCRIPT" --execute "$IMAGE"; then
  die "Failed configuration accepted (no previous override)"
fi
[[ ! -e "$DEPLOY_ROOT/compose.deploy.yaml" ]] ||
  die "Rollback failed to remove a newly created override"

# Happy path must persist the approved immutable image override.
: > "$MOCK_LOG"
bash "$SCRIPT" --execute "$IMAGE"
grep -q "$IMAGE" "$DEPLOY_ROOT/compose.deploy.yaml" ||
  die "Approved image not applied"
grep -q '^backup$' "$MOCK_LOG" || die "Backup hook did not run"
grep -q '^docker pull ' "$MOCK_LOG" || die "Image not pulled"
# A redirect or failure status must trigger rollback instead of false success.
: > "$MOCK_LOG"
if MOCK_HEALTH_HTTP=301 bash "$SCRIPT" --execute "$IMAGE"; then
  die "HTTP redirect was incorrectly accepted as healthy"
fi
grep -q 'X-Forwarded-Proto: https' "$MOCK_LOG" || die "Forwarded scheme not sent"
grep -q '^docker compose .*up -d --no-deps web worker' "$MOCK_LOG" || die "Redirect did not trigger rollback"
echo "MOCK_DEPLOY_PASS: schema gate, backup fail-closed, rollback, strict 200, success"
