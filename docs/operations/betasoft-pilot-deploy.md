# Beta Soft OpenProject — portable CI/CD and multi-host deployment

## Scope

Provider-neutral application delivery to **AWS EC2, a VPS, another AWS account,
or other Linux VMs** with Docker Compose. The existing GHCR build workflow remains
unchanged and is responsible for building and scanning the immutable image.

The new workflow `Fork / Prepare portable release` runs manually on `dev`, accepts
a previously reviewed GHCR image SHA256 digest, selects one of `pilot`, `staging`,
or `production`, and uploads a release bundle with the image reference and
deployment scripts. It **does not** connect to any host, perform an AWS operation,
or change production. The GitHub Environment provides an optional approval gate
depending on repository settings and available plan features. Protect the release
workflow and target environments.

This is a *release-preparation* pipeline, **not yet unattended CD**. Automatic
promotion by a host-side agent is a separate phase, after backup restore drills,
image authenticity verification, and deployment approval controls.

## Portable execution on any Linux host

Prerequisites: Docker Engine + Docker Compose plugin, bash, curl, flock, the
application's `compose.yaml`, running PostgreSQL, a verified secure backup hook,
and authenticated access to the image registry when GHCR is private.

The host deployment command should run only from a trusted, verified bundle,
not an arbitrary script downloaded from an untrusted URL. Review its SHA256SUMS
and source commit. Place the files in a protected directory with restricted
permissions. Never execute unreviewed PR artifacts as root.

First test without modifying anything:

```bash
DEPLOY_ROOT=/opt/openproject-pilot \
  bash ./deploy.sh --dry-run ghcr.io/aristha/openproject@sha256:<64-hex-digest>
```

For the AWS pilot, after reviewing release compatibility, **restore testing** and
backup scripts, configure:

```bash
chmod 700 ./aws-s3-backup.sh
export DEPLOY_ROOT=/opt/openproject-pilot
export DEPLOY_HOST=projects.betajapansoftware.com
export DEPLOY_HEALTH_URL=http://127.0.0.1:8080/health_check
export DEPLOY_BACKUP_HOOK="$(pwd)/aws-s3-backup.sh"
export S3_BACKUP_BUCKET=betasoft-openproject-backups-080891697921-ap-southeast-2-an
export AWS_REGION=ap-southeast-2
export DEPLOY_SCHEMA_APPROVED=NO_MIGRATIONS
sudo --preserve-env=DEPLOY_ROOT,DEPLOY_HOST,DEPLOY_HEALTH_URL,DEPLOY_BACKUP_HOOK,S3_BACKUP_BUCKET,AWS_REGION,DEPLOY_SCHEMA_APPROVED \
  bash ./deploy.sh --execute ghcr.io/aristha/openproject@sha256:<64-hex-digest>
```

**Never use the placeholder digest literally.** Use only a successful, approved
GHCR build digest. Verify that the currently deployed image and candidate are
schema-compatible. If a release requires database migrations, do not use this
script as-is; develop migration and rollback procedures first.

For another provider, replace only `DEPLOY_BACKUP_HOOK` with an executable
script that produces and verifies an off-host, restorable database and attachment
backup. Do not pass database passwords, access keys, or tunnel credentials into
GitHub Actions. Secure backups and encryption policy remain operator duties.

On-host deploy enforces an immutable GHCR digest, a single-deploy lock, running
database, required backup hook, local HTTP check, and Web/Worker running status.
It only changes their Docker Compose image override. On deployment failure it
attempts image-only rollback, **not database recovery**. Restore tests and a
maintenance window are necessary to protect consistency between PostgreSQL and
attachments. Backup size checks and SHA256 are **not** a restore test.

Note: the AWS adapter requires Docker pull permission for `alpine:3.21`, the
AWS CLI, and an EC2 instance role able to write the backup bucket. It verifies
S3 uploaded object byte lengths. Use a maintenance window if users might upload
attachments during the backup.

All subsequent Docker Compose commands on the host must include the overlay:

```bash
docker compose -f compose.yaml -f compose.deploy.yaml ps
```

Do not `docker compose up -d` without the overlay after a successful deployment
unless intentionally reverting to the base compose image.

## Multi-host / multi-cloud design

- **Build once**: GHCR OCI image pinned by sha256 is independent of AWS account.
- **Promote by environment**: separate GitHub release bundles for pilot,
  staging, production. A production rollout requires its own approval.
- **Deploy on each host**: local script with a provider-specific backup hook.
  No inbound SSH and no GitHub cloud credentials are needed for manual mode.
- **Configure externally**: hostnames, secrets, persistent volumes, TLS route,
  database credentials, ports, S3/bucket, uptime schedule, and monitoring remain
  host/provider configuration.
- **Preserve state**: PostgreSQL + OpenProject attachments + SECRET_KEY_BASE.
  A Docker image is not a data migration.
- **Scale topology**: this script is designed for a **single Docker Compose
  installation**. Running multiple replicas against one DB requires shared
  attachment storage, singleton scheduler/worker architecture, database
  capacity checks, and an HA migration design. It is NOT implemented here.
- **Future AWS account**: re-provision IAM/SSM, volumes, private networking,
  S3 backup and Cloudflare routing in the destination account; restore and
  test before switching traffic. No GitHub OIDC needed for the manual mode.

## Remaining release gates

- [ ] Validate base Compose service/volume names and health endpoint on pilot.
- [ ] Demonstrate backup restoration on a separate PostgreSQL and assets volume.
- [ ] Confirm secure image-pull authentication if GHCR visibility changes.
- [ ] Run release workflow with a known digest and inspect uploaded artifact.
- [ ] Dry-run on the pilot host, no production changes.
- [ ] Review app migrations and arrange maintenance window.
- [ ] Test rollback for image-only deployment and alerts.
- [ ] Add automated host-side reconciliation only after production controls.
- [ ] Add Terraform/OpenTofu provider-specific infrastructure as separate PR.

## Security decisions

The AWS Free Plan has an explicit SCP deny on IAM GetOpenIDConnectProvider.
Do not attempt to bypass it. This PR intentionally removes the direct
GitHub-OIDC-to-SSM workflow; it does **not** use long-lived AWS keys or SSH
secrets in GitHub. Release bundles may be downloaded by authorized operators
and deployed from each host via existing access (SSM or console).

GitHub release bundle preparation does not claim the supplied image digest was
cryptographically verified against GHCR or CI provenance; operators must
check the build and image digest before promotion.

## Optional weekday AWS backup timer (not installed automatically)

The templates in `deploy/systemd/` schedule an S3 backup at **17:45
Asia/Ho_Chi_Minh Monday–Friday**, before the intended 18:30 EC2 stop. The
service has a 25-minute timeout and does **not** start a stopped EC2 instance.
`Persistent=false` prevents catch-up jobs after a machine was offline.

This is an **optional AWS adapter**, not part of the cloud-neutral runtime.
Inspect and adapt paths before installation. The AWS S3 backup script
`deploy/adapters/aws-s3-backup.sh` assumes the existing backup IAM role and
PostgreSQL/attachments Compose layout.

On the EC2 **only after operator review**, install the files using the trusted
release bundle or a pinned repository commit:

```bash
sudo install -D -m 0750 deploy/adapters/aws-s3-backup.sh \
  /usr/local/libexec/betasoft-aws-s3-backup.sh
sudo install -D -m 0644 deploy/systemd/betasoft-openproject-backup.service \
  /etc/systemd/system/betasoft-openproject-backup.service
sudo install -D -m 0644 deploy/systemd/betasoft-openproject-backup.timer \
  /etc/systemd/system/betasoft-openproject-backup.timer
sudo install -d -m 0700 /etc/betasoft
printf 'S3_BACKUP_BUCKET=%s\n' \
  'betasoft-openproject-backups-080891697921-ap-southeast-2-an' \
  | sudo tee /etc/betasoft/openproject-backup.env >/dev/null
sudo chmod 0600 /etc/betasoft/openproject-backup.env
sudo systemd-analyze calendar 'Mon..Fri *-*-* 17:45:00 Asia/Ho_Chi_Minh'
sudo systemctl daemon-reload
sudo systemctl enable --now betasoft-openproject-backup.timer
sudo systemctl list-timers betasoft-openproject-backup.timer
```

Test it manually during a planned maintenance window with
`sudo systemctl start betasoft-openproject-backup.service`, inspect
`sudo journalctl -u betasoft-openproject-backup.service --no-pager -n 80`,
then check all uploaded object sizes, checksum manifest and bucket permissions.

**Consistency warning:** A live PostgreSQL logical dump plus a separate live
attachments tarball is *not* an atomic DB/files snapshot. A fully consistent
backup for changes involving uploads must be taken during an application
maintenance/write-quiesced window. Do not close recovery issue #5 until
database and assets are actually restored and verified on an isolated host.
Set up backup freshness alarms and S3 retention separately.

If the EC2 Stop schedule is wrong, enabling this timer does not fix it. Verify
EventBridge Start/Stop independently. Do not enable the timer on future
non-AWS hosts without replacing the backup adapter.

## Release bundle integrity gate (added in PR #3)

The `Fork / Prepare portable release` workflow now validates a generated
bundle locally before artifact upload. An operator can re-check an extracted
artifact on any Python 3 host by running the verifier from the exact reviewed
source commit:

```bash
python3 deploy/portable/verify_release.py /absolute/path/to/extracted-release
```

A valid bundle has only `release.json`, `SHA256SUMS`, `deploy.sh`,
`aws-s3-backup.sh`, `betasoft-openproject-backup.service` and
`betasoft-openproject-backup.timer`. Checksum entries are relative to the
bundle directory. It checks digest syntax, source revision, environment channel
and the `not-performed` migration declaration.

**Security limit:** checksums contained in the same artifact detect accidental
corruption and inconsistent packaging, but a malicious actor able to replace
the entire artifact could replace its checksums too. They **do not** prove image
provenance, trusted approval, or correct database migration. For production,
reconcile source SHA, the reviewed GHCR build job and immutable image digest
independently; use GitHub environment protections and explicit approval.
Deployment remains manual on each host.

CI also exercises schema gate, fail-closed backup and configuration rollback
using mocked `docker` and `curl`; these checks do **not** prove real host
rollback or application recovery. Never run an image migration based only on
these tests.
