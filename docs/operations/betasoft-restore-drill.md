# Beta Soft P0 — Isolated backup restore drill

Tracks Issue #5 and Epic #4. This drill does **not** alter the running OpenProject
Docker Compose project, database, attachments volume, or app secrets.

## Why

`pg_dump` and an uploaded S3 object prove only that files exist. The on-disk
database dump must successfully restore, while the attachments archive must
extract safely into an isolated path. This is a structural drill; user workflow
and actual application access are a separate acceptance gate.

## Requirements

- A **separate disposable Linux VM** preferred. Do not run on the small,
  active pilot EC2 without a maintenance window and resource review.
- Docker Engine, tar, sha256sum, adequate scratch disk and Docker space.
- Restricted operator access to the existing S3 backup files.
- No AWS credentials embedded in scripts or GitHub Actions logs.
- Backup directory contains `database.dump`, `assets.tar.gz`, `SHA256SUMS`.
  The original manual backup's checksum manifest must be created only after
  verifying hashes against a known trusted source. Never silently generate a
  manifest from potentially corrupt downloads and claim authenticity.

## Get a copy of an existing backup

For the initial pilot backup, use a secure isolated host with an appropriate
AWS identity and *read-only* S3 permissions:

```bash
mkdir -m 700 -p "$HOME/op-restore-input"
aws s3 cp \
  s3://betasoft-openproject-backups-080891697921-ap-southeast-2-an/manual/20261107T131904Z/database.dump \
  "$HOME/op-restore-input/database.dump" --region ap-southeast-2
aws s3 cp \
  s3://betasoft-openproject-backups-080891697921-ap-southeast-2-an/manual/20261107T131904Z/assets.tar.gz \
  "$HOME/op-restore-input/assets.tar.gz" --region ap-southeast-2
```

**Important:** That historic backup was originally uploaded with the two files,
not necessarily SHA256SUMS. The drill script intentionally refuses backups
without trusted checksums. Record SHA256 from the trusted original local copy
or create a separately verified baseline after inspecting dump structure and
archive, and document this limitation. Future backup jobs must upload
SHA256SUMS alongside both files.

For newer automated deploy backups, download the three files from the same
`deploy/<timestamp>/` prefix.

## Run only after checksum provenance is established

```bash
bash deploy/recovery/isolated-restore-drill.sh "$HOME/op-restore-input"
```

The script checks archive checksums, extracts attachments into a fresh
temporary directory, creates a **new disposable PostgreSQL 17** container
with no published ports and disabled networking, restores the custom dump into
a separate test DB, counts public tables and attachment files (no user data
printed), and deletes the temporary container and scratch files on exit.

The disposable postgres container uses trust authentication strictly inside
an isolated no-network instance; do **not** copy this setting into production.
Do not run arbitrary database scripts from untrusted sources.

## Definition of Done

- [ ] Source backup integrity and date verified.
- [ ] `RESTORE_DRILL_PASS` recorded without sensitive contents.
- [ ] Representative attachments open and ownership/paths are valid when app
      runs in isolated restored test environment.
- [ ] Application login, projects and work packages verified on isolated host.
- [ ] Backup retention, alerts and RPO/RTO documented.
- [ ] Procedure rerun after changes to backup format or OpenProject version.

A structural restore alone does not close Issue #5. If pg_restore fails because
the disposable PostgreSQL image lacks required extensions, record the exact
extension and use a version-compatible test image rather than suppressing the
error or changing production.

## Pilot historical backup: verify S3 against retained originals

The initial backup was captured at `/var/backups/openproject/20261107T131904Z`
and uploaded to
`s3://betasoft-openproject-backups-080891697921-ap-southeast-2-an/manual/20261107T131904Z/`.

If the **original local directory still exists** and has not been modified, the
following wrapper compares each remote file with its original using SHA256.
Only when hashes match will it generate a temporary manifest and attempt the
isolated structural restore. No upload, production DB connection, or production
volume change is performed. This relies on the retained local original as the
integrity baseline; independently preserve that evidence.

Run only during an approved maintenance window and ideally on a disposable
copy of the VM; Docker still consumes CPU, memory and disk on the execution
host. The initial production host has limited memory, so measure capacity first.

```bash
# Confirm file existence, sizes and current EC2 resource headroom.
sudo ls -lh /var/backups/openproject/20261107T131904Z/{database.dump,assets.tar.gz}
free -h
df -h /

# After obtaining this PR at a reviewed commit, run both scripts from a
# trusted read-only directory; adjust to absolute file paths:
sudo bash /absolute/path/verify-s3-manual-backup.sh \
  s3://betasoft-openproject-backups-080891697921-ap-southeast-2-an/manual/20261107T131904Z \
  /var/backups/openproject/20261107T131904Z \
  /absolute/path/isolated-restore-drill.sh
```

Capture **only** the terminal lines `S3_OBJECT_MATCH`, `S3_COMPARE_PASS`,
`RESTORED_TABLE` (aggregate counts only) and `RESTORE_DRILL_PASS` in Issue #5.
The S3 wrapper requires `users`, `projects`, `work_packages` and `attachments`
tables to exist in the restored database.
Do not paste passwords, access tokens, complete dump data, or attachment
contents. If local original missing, do not fabricate a trusted manifest;
obtain a fresh backup with recorded hashes and verify its origin.

The wrapper reads from S3 using the instance's existing role. If an S3 policy
does not permit GetObject, fix the policy through the authorized IAM flow;
do not embed credentials in the script.

### Additional application-level validation (still required)

Structural restore does not verify usability. Run a complete **isolated**
OpenProject instance with a restored database and attachment directory,
carrying over the original runtime encryption key from a secure channel.
Prove the following with non-sensitive evidence:

- Users and project counts agree with the source before cutover.
- A representative work package is visible.
- A representative attachment is downloadable and the byte hash matches.
- Worker starts and health checks pass without operating against live DB.
- A separate simulated failure can be reversed with the written recovery steps.

**Do not close Issue #5** until these checks, scheduled backup execution,
S3 controls and RPO/RTO are recorded; CI synthetic restore only validates
the tool, not the production backup.
