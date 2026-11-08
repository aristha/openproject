# Phase 2: approved GitHub Actions release transport (source only)

This component is separate from Phase 1's agent and **never deploys**. It cannot
create `approval.json`, automatically select the newest artifact, start an EC2,
or activate a timer. Default mode verifies only; opt-in `--stage` writes only
the ZIP to the root-owned Phase 1 inbox.

## Exact, independent authorization

An administrator prepares `/etc/betasoft/approved-release/transport-request.json`
(0600, root owned) with **all** of the following keys:

```json
{
  "schema_version": 1,
  "run_id": 123456,
  "artifact_id": 789012,
  "artifact_sha256": "<actual 64-character SHA256 of GitHub artifact ZIP>",
  "environment": "pilot",
  "source_sha": "<release workflow's 40-character commit SHA>",
  "image": "ghcr.io/aristha/openproject@sha256:<approved image digest>",
  "expires_at": "<ISO-8601 timestamp within 7 days>"
}
```

The existing independently prepared root-owned `approval.json` must match the
exact ZIP digest, image, source SHA and environment. The transporter does
not create or modify the approval. Neither a GitHub workflow's success nor its
reported artifact digest is independent authorization.

For private repository access, create a fine-grained GitHub token scoped to
`aristha/openproject` with **Actions: read** only. Store it in a root-owned
0600 file at `/etc/betasoft/release-transport/github-token`. Do not put
tokens into command lines, CI, systemd environment or logs.

The transporter fetches workflow run and artifact metadata from the fixed
GitHub REST API origin, requiring the correct workflow path, repository, exact
`dev` SHA, successful manual workflow dispatch, artifact ID/run membership,
expected name, and unexpired artifact. It retrieves artifact ZIP through the
GitHub signed redirect, forwarding **no bearer token** to storage. Only HTTPS
GitHub/Azure artifact domains are allowed, then validates downloaded bytes,
internal bundle checksums, and manifest against the independent approval.
New storage hostnames fail closed pending review.

**Important:** `release.json.source_sha` identifies the release packaging
workflow's source, **not** the GHCR image build source. Full cryptographic
image provenance (signed OCI/SLSA attestation and policy evaluation) remains
unimplemented. Independently review GHCR build provenance before operator
approval; do not enable unattended deployment based on transport checks.

## Optional installation (NOT carried out by this PR)

Install the new Python file alongside `approved_release_agent.py` and
`verify_release.py` from a reviewed, pinned commit. Install the supplied
systemd template only after operator approval. Create the following root-only
paths, ensuring non-writable, non-symlink ancestor directories:

- `/etc/betasoft/approved-release` (0700), containing request and existing approval
- `/etc/betasoft/release-transport` (0700), containing read-only GitHub token
- `/var/lib/betasoft-release-agent` (0700), containing JSONL audit file
- `/var/lib/betasoft-release-agent/alerts` (0700), containing failure alert files

Verification only (no ZIP staging):

```bash
sudo python3 /usr/local/libexec/betasoft-release-agent/agent/release_transport.py
```

Explicitly authorized ZIP staging (NEVER deploy):

```bash
sudo python3 /usr/local/libexec/betasoft-release-agent/agent/release_transport.py --stage
```

Do not schedule either command or enable agent execution before Issue #6
live rollback and Issue #5 recovery readiness are accepted.

## Audit, failure alerts and limitations

Transport writes bounded structured JSON events to stdout/journald and a
root-only JSONL audit file. On rejection it exits nonzero and adds a root-only
JSON file to `alerts/` for an external monitoring consumer, without logging
bearer tokens or signed storage links. **The alert spool is not an external
notification delivery guarantee.** Connect and test an on-call receiver,
delivery retries and freshness alarms separately before claiming operational
alerting. No webhook or other outbound secret is configured by this PR.

Run offline tests:

```bash
python3 -m unittest discover -s deploy/agent -p 'test_release_transport.py' -v
```

Threat boundaries: operator/root compromise, malicious but approved artifacts,
a compromised image publisher, and database recovery are not solved by this
component. ZIP staging does not modify running containers, cloud resources,
systemd flags or databases. Staging must not be equated with rollback acceptance.
