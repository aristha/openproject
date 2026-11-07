#!/usr/bin/env bash
# Verify a previously uploaded AWS S3 backup against its retained LOCAL ORIGINAL.
# This script does not change existing DB or Docker volumes.
set -Eeuo pipefail
umask 077

if [[ $# != 3 ]]; then
  echo "Usage: $0 s3://BUCKET/PREFIX /absolute/local-original-dir /absolute/restore-drill.sh" >&2
  exit 2
fi
S3_PREFIX="$1"
ORIGINAL="$2"
DRILL="$3"

[[ "$S3_PREFIX" =~ ^s3://[a-z0-9][a-z0-9.-]{2,62}/[a-zA-Z0-9_./-]+$ ]] || {
  echo "Invalid S3 prefix"; exit 2;
}
[[ "$ORIGINAL" == /* && -d "$ORIGINAL" && "$DRILL" == /* && -f "$DRILL" ]] || {
  echo "Original backup directory and verified drill script must be absolute paths" >&2; exit 2;
}
for x in aws sha256sum mktemp stat bash; do command -v "$x" >/dev/null; done
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

echo "Checking S3 backup against local originals (no secrets displayed)"
for f in database.dump assets.tar.gz; do
  [[ -s "$ORIGINAL/$f" ]] || { echo "Local original is missing $f"; exit 1; }
  aws s3 cp "$S3_PREFIX/$f" "$WORK/$f" --only-show-errors
  original_hash="$(sha256sum "$ORIGINAL/$f" | cut -d ' ' -f 1)"
  remote_hash="$(sha256sum "$WORK/$f" | cut -d ' ' -f 1)"
  [[ "$original_hash" == "$remote_hash" ]] || {
    echo "S3 vs LOCAL ORIGINAL hash mismatch for $f" >&2
    exit 1
  }
  echo "S3_OBJECT_MATCH $f bytes=$(stat -c %s "$WORK/$f") sha256=$original_hash"
done

# The retained original is our baseline; document how it was preserved.
# This does not prove authenticity if the original itself was compromised.
(cd "$WORK" && sha256sum database.dump assets.tar.gz > SHA256SUMS)
echo "S3_COMPARE_PASS: downloaded files match the retained local originals"
bash "$DRILL" "$WORK"
