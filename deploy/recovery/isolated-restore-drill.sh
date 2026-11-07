#!/usr/bin/env bash
# Isolated, read-only input restore drill. NEVER connects to production DB.
set -Eeuo pipefail
umask 077

if [[ $# -ne 1 || ! -d "$1" ]]; then
  echo "Usage: $0 /absolute/path/to/downloaded-backup" >&2
  exit 2
fi
INPUT="$(cd "$1" && pwd -P)"
[[ -s "$INPUT/database.dump" && -s "$INPUT/assets.tar.gz" ]] || {
  echo "Required database.dump and assets.tar.gz not found" >&2
  exit 2
}
for binary in docker tar sha256sum find mktemp python3; do command -v "$binary" >/dev/null; done

if [[ -f "$INPUT/SHA256SUMS" ]]; then
  (cd "$INPUT" && sha256sum --check --status SHA256SUMS) || {
    echo "Backup SHA256SUMS verification failed" >&2; exit 1;
  }
else
  echo "WARNING: SHA256SUMS missing; provenance/integrity cannot be established" >&2
  exit 1
fi

WORK="$(mktemp -d)"
NAME="op-restore-drill-$(basename "$WORK" | tr -dc 'a-zA-Z0-9')"
cleanup() {
  docker rm -f -v "$NAME" >/dev/null 2>&1 || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK/assets"
# First inspect attachment archive and then restore into temporary, isolated directory.
tar -tzf "$INPUT/assets.tar.gz" >/dev/null
# Python's 'data' extraction filter rejects traversal, absolute paths and unsafe links.
# Do not trust file names stored inside a remote backup archive.
python3 - "$INPUT/assets.tar.gz" "$WORK/assets" <<'PY'
import sys
import tarfile

archive_path, output_dir = sys.argv[1:]
with tarfile.open(archive_path, mode="r:gz") as archive:
    archive.extractall(output_dir, filter="data")
PY
ASSET_COUNT="$(find "$WORK/assets" -type f | wc -l)"
echo "Assets restored to isolated scratch directory; file_count=$ASSET_COUNT"

# No published ports and no network: the disposable DB is inaccessible remotely.
# Trust authentication is scoped solely to this ephemeral isolated container.
docker run -d --name "$NAME" --network none \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  --mount "type=bind,source=$INPUT,target=/backup,readonly" \
  postgres:17 -c shared_buffers=64MB -c max_connections=20 >/dev/null

ready=no
for _ in $(seq 1 30); do
  if docker exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; then ready=yes; break; fi
  sleep 2
done
[[ "$ready" == yes ]] || { echo "Disposable PostgreSQL failed to start" >&2; exit 1; }
docker exec "$NAME" createdb -U postgres openproject_restore_test
docker exec "$NAME" pg_restore --list /backup/database.dump >/dev/null
docker exec "$NAME" pg_restore \
  --exit-on-error --no-owner --no-acl -U postgres \
  -d openproject_restore_test /backup/database.dump
TABLE_COUNT="$(docker exec "$NAME" psql -U postgres -d openproject_restore_test -Atc \
  "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public'")"
[[ "$TABLE_COUNT" =~ ^[0-9]+$ && "$TABLE_COUNT" -gt 0 ]] || {
  echo "Restore did not create user tables" >&2; exit 1;
}
echo "RESTORE_DRILL_PASS: PostgreSQL public tables=$TABLE_COUNT; asset_files=$ASSET_COUNT"
echo "This is a structural restore only. Application-level smoke tests and secrets validation remain outstanding."
