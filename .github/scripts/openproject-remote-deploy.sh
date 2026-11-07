#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
IMAGE="$1"
BUCKET="$2"
ROOT=/opt/openproject-pilot
REGION=ap-southeast-2
OVERRIDE=compose.deploy.yaml
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DIR="/var/backups/openproject/$STAMP"
[[ "$IMAGE" =~ ^ghcr\.io/aristha/openproject@sha256:[a-f0-9]{64}$ ]] || { echo "Invalid immutable image" >&2; exit 1; }
[[ "$BUCKET" =~ ^[a-z0-9][a-z0-9.-]{2,62}$ ]] || exit 1
cd "$ROOT"
docker compose config --quiet
docker compose exec -T db pg_isready -U openproject -d openproject >/dev/null
[[ "$(df --output=avail -B1 / | tail -1)" -ge 8589934592 ]] || { echo "Insufficient disk space" >&2; exit 1; }
aws s3api head-bucket --bucket "$BUCKET" --region "$REGION"
mkdir -p "$DIR"
chmod 700 "$DIR"
docker compose exec -T db pg_dump -U openproject -d openproject -Fc --no-owner --no-acl > "$DIR/database.dump"
test -s "$DIR/database.dump"
docker compose exec -T db pg_restore --list < "$DIR/database.dump" >/dev/null
WEB_ID=$(docker compose ps -q web)
test -n "$WEB_ID"
VOLUME=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/openproject/assets"}}{{.Name}}{{end}}{{end}}' "$WEB_ID")
test -n "$VOLUME"
docker run --rm --mount "type=volume,source=$VOLUME,target=/assets,readonly" --mount "type=bind,source=$DIR,target=/backup" alpine:3.21 tar -czf /backup/assets.tar.gz -C /assets .
tar -tzf "$DIR/assets.tar.gz" >/dev/null
(cd "$DIR" && sha256sum database.dump assets.tar.gz > SHA256SUMS)
for file in database.dump assets.tar.gz SHA256SUMS; do
 aws s3 cp "$DIR/$file" "s3://$BUCKET/deploy/$STAMP/$file" --region "$REGION" --sse AES256 --only-show-errors
 aws s3api head-object --bucket "$BUCKET" --key "deploy/$STAMP/$file" --region "$REGION" --query ContentLength --output text >/dev/null
done
echo "Backup gate passed: s3://$BUCKET/deploy/$STAMP/"
# No DB migrations. Operator must review migrations separately before approving this workflow.
docker pull "$IMAGE"
OLD_IMAGE=$(docker inspect --format '{{.Config.Image}}' "$WEB_ID")
if test -f "$OVERRIDE"; then cp "$OVERRIDE" "$OVERRIDE.previous"; HAD_OVERRIDE=yes; else HAD_OVERRIDE=no; fi
rollback() {
 rc=$?
 trap - ERR
 echo "Deployment failed; attempting image rollback" >&2
 if test "$HAD_OVERRIDE" = yes; then
   cp "$OVERRIDE.previous" "$OVERRIDE"
   docker compose -f compose.yaml -f "$OVERRIDE" up -d --no-deps web worker || true
 else
   rm -f "$OVERRIDE"
   docker compose up -d --no-deps web worker || true
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
HEALTHY=no
for n in $(seq 1 36); do
 if curl --silent --fail --max-time 8 -o /dev/null -H 'Host: projects.betajapansoftware.com' http://127.0.0.1:8080/health_checks/default; then HEALTHY=yes; break; fi
 sleep 10
done
test "$HEALTHY" = yes
for svc in web worker; do
 CID=$(docker compose -f compose.yaml -f "$OVERRIDE" ps -q "$svc")
 test -n "$CID"
 test "$(docker inspect --format '{{.State.Running}}' "$CID")" = true
done
trap - ERR
echo "DEPLOY_SUCCESS image=$IMAGE previous=$OLD_IMAGE backup=s3://$BUCKET/deploy/$STAMP/"
