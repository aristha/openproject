# Beta Soft OpenProject: pilot deployment via GitHub Actions

## Scope and safety

This is a **manual, pilot-only** deployment workflow. Nothing deploys on PR or merge. The
existing GHCR build workflow is unchanged. Initial runs must use **dry_run=true**.
The workflow requires branch dev, a human confirmation string for real deployments,
and an optional GitHub Environment approval policy.

**Not yet production-certified:** A database restore exercise, runtime SSM/OIDC
connectivity test, and GHCR image lifecycle/security review are required before
enabling real deployment. This code deliberately does **not** run database migrations
or seeds. If a release needs migrations, DO NOT run this workflow until a separate,
reviewed migration/rollback procedure exists.

## GitHub environment: pilot

Create a GitHub Actions Environment called pilot. Configure reviewer approval if
your GitHub plan and repository visibility support it; do not assume approvals
are enforced without verifying the UI. Set these environment variables:

- AWS_DEPLOY_ROLE_ARN: AWS OIDC role ARN for this deployment environment.
- EC2_INSTANCE_ID: instance ID (pilot: i-0e813ed245633d925).
- S3_BACKUP_BUCKET: bucket name (pilot:
  betasoft-openproject-backups-080891697921-ap-southeast-2-an).

No AWS long-lived access keys, SSH private keys, PostgreSQL passwords or
Cloudflare tokens belong in GitHub Actions.

### IAM prerequisite (in each target AWS account)

1. Create GitHub OIDC identity provider for token.actions.githubusercontent.com,
   audience sts.amazonaws.com, according to current AWS/GitHub documentation.
2. Create a GitHub Actions role with sts:AssumeRoleWithWebIdentity. Restrict
   token.actions.githubusercontent.com:aud to sts.amazonaws.com and sub to the
   exact repository/environment identity. For older repository OIDC subject
   formats the sub is typically repo:aristha/openproject:environment:pilot;
   **inspect the real token claim** and account for newer organization/repository
   immutable-ID claim conventions. Do not use wildcard repository trust.
3. Grant this GitHub role only ec2:DescribeInstances for verification,
   ssm:SendCommand scoped to the exact EC2 instance and the AWS-RunShellScript
   document, and ssm:GetCommandInvocation. CloudTrail records the action.
4. The EC2 instance profile must separately include AmazonSSMManagedInstanceCore
   plus its existing minimal S3 backup permissions (ListBucket, PutObject,
   GetObject). SSM Agent must be online. Use SSM managed node check before
   real deployment. Confirm S3 prefix write works. Never replace the
   backup role with an unrelated role.
5. AWS target region is ap-southeast-2 for this pilot. Multi-account migration
   changes environment variables and IAM/SSM setup, not the GitHub repo and GHCR
   image. If the future account uses another region, parameterize and review
   region constraints first.

### Manual run

1. Confirm the GHCR **digest** comes from a successful, fully scanned
   Fork / Build slim image to GHCR run.
2. Run the workflow on dev with image_digest = sha256:<64 hex> and dry_run=true.
3. Check script validation result, then establish OIDC/SSM and restore test.
4. Confirm app/database changes have **no schema migration requirement**.
5. For authorized pilot test only: use dry_run=false and confirmation =
   DEPLOY_NO_MIGRATIONS. Check SSM command output and post-deploy user flow.

Deployment checks EC2 state and refuses to start a stopped machine (to avoid
unscheduled charges). It backs up pg_dump and attachments to S3, changes only
web/worker Docker image through compose.deploy.yaml, then checks HTTP health.
On failure it attempts **image-only rollback**. Rollback does NOT restore the
database; DB and attachments consistency is not guaranteed while users upload
files. For data-affecting releases schedule a maintenance window with writes
disabled, verified backup and an independently tested recovery plan.

IMPORTANT: When using the host manually, always run
  docker compose -f compose.yaml -f compose.deploy.yaml ...
after deployment. Plain docker compose up without the override may revert
web/worker to the image hardcoded in compose.yaml.

## EC2 backup/recovery controls

- The manual backup created at S3 manual/20261107T131904Z contains database.dump
  and assets.tar.gz but a full restore rehearsal has NOT been established.
- No .env or credentials are uploaded by the deployment script.
- Preserve SECRET_KEY_BASE separately in a secure password/secrets manager and
  preserve encrypted backup of runtime config. The current pilot .env includes
  database password and Cloudflare Tunnel token.
- Enable S3 bucket public access block, SSE-S3, versioning and a lifecycle policy.
  Confirm the actual S3 bucket permissions and versioning in AWS.
- Keep enough EBS free space and set CloudWatch alarm thresholds.
- Backups from running DB and running attachment volume are not atomic;
  planned migration requires transactional/maintenance procedures.

## Future AWS account migration

Provision a new Ubuntu EC2 and Docker Compose with PostgreSQL and assets volumes,
SSM Agent and instance profile; re-create S3, CloudWatch, EventBridge schedules
and the Cloudflare Tunnel connector. Restore verified DB and assets under
maintenance, and preserve production secrets. Point the Cloudflare public hostname
to the tested new origin, validate login/work packages, then retire old EC2 only
after a defined rollback window. Infrastructure-as-code for these resources is
a separate follow-up and is not claimed to be implemented by this PR.
