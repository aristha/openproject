#!/usr/bin/env bash
# AWS S3 backup adapter; invoked on host by deploy/portable/deploy.sh.
set -Eeuo pipefail
umask 077
BUCKET="${S3_BACKUP_BUCKET:?Set S3_BACKUP_BUCKET}"
REGION="${AWS_REGION:-ap-southeast-2}"
ROOT="${DEPLOY_ROOT:-/opt/openproject-pilot}"
DEST="${BACKUP_ROOT:-/var/backups/openproject}/$(date -u +%Y%m%dT%H%M%SZ)"
[[ "$BUCKET" =~ ^[a-z0-9][a-z0-9.-]{2,62}$ ]] || exit 2
cd "$ROOT"
mkdir -p "$DEST"
chmod 700 "$DEST"
aws s3api head-bucket --bucket "$BUCKET" --region "$REGION"
docker compose -f compose.yaml exec -T db pg_dump -U openproject -d openproject -Fc --no-owner --no-acl > "$DEST/database.dump"
test -s "$DEST/database.dump"
docker compose -f compose.yaml exec -T db pg_restore --list < "$DEST/database.dump" >/dev/null
WEB="$(docker compose -f compose.yaml ps -q web)"
test -n "$WEB"
VOLUME="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/openproject/assets"}}{{.Name}}{{end}}{{end}}' "$WEB")"
test -n "$VOLUME"
docker run --rm --mount "type=volume,source=$VOLUME,target=/assets,readonly" --mount "type=bind,source=$DEST,target=/backup" alpine:3.21 tar -czf /backup/assets.tar.gz -C /assets .
tar -tzf "$DEST/assets.tar.gz" >/dev/null
(cd "$DEST" && sha256sum database.dump assets.tar.gz > SHA256SUMS && sha256sum -c SHA256SUMS)
for item in database.dump assets.tar.gz SHA256SUMS; do
  aws s3 cp "$DEST/$item" "s3://$BUCKET/deploy/$(basename "$DEST")/$item" --region "$REGION" --sse AES256 --only-show-errors
  COUNT=$(aws s3api head-object --bucket "$BUCKET" --key "deploy/$(basename "$DEST")/$item" --region "$REGION" --query ContentLength --output text)
  test "$COUNT" -eq "$(stat -c %s "$DEST/$item")"
done
echo "AWS S3 backup verified for remote existence and byte lengths; RESTORE NOT YET TESTED."
