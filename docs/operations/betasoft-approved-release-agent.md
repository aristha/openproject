# BetaSoft approved-release host agent — rollout gates

## State and threat model

This is **phase 1 of automatic deployment**, intentionally **disabled for execution** by
default. The host polls a root-controlled **local inbox**, not GitHub directly.
A trusted administrator must independently verify the GHCR build, downloaded
GitHub Actions release ZIP and SHA-256, then stage a release-specific approval
file. GitHub Actions release bundle hashes alone **do not authenticate**
GitHub build provenance: the agent compares the approved ZIP byte hash with
the staged ZIP and validates all internal SHA256SUMS as defense in depth.

Attacker paths addressed: altered ZIP, extra/path-traversal entries, stale
approval, wrong environment/image/source, disallowed DB migrations, concurrent
reconciliations, execution without explicit enable flag, and off-hours deploys.
**Not addressed**: root compromise, malicious administrator approvals, a
compromised signed-off image/build, a rogue registry image matching an
approved digest, DB schema rollback, and loss of production data. Host ZIP
delivery and incident notifications are intentionally left to a later,
authenticated transport/monitoring integration.

**Do not copy an approval JSON from CI or accept auto-generated approvals.**
The approval is a separate operator decision. The instance retains its
existing 08:30–18:30 weekday schedule, and this agent cannot start EC2.

## Safe installation — optional; observer only

After reviewing and merging this PR, download from a **pinned commit** or
approved source checkout. Run on the pilot EC2 only after reviewing paths:

```bash
sudo install -d -o root -g root -m 0700 /etc/betasoft/approved-release
sudo install -d -o root -g root -m 0700 /var/lib/betasoft-release-agent
sudo install -d -o root -g root -m 0750 /usr/local/libexec/betasoft-release-agent/agent
sudo install -d -o root -g root -m 0750 /usr/local/libexec/betasoft-release-agent/portable
sudo install -o root -g root -m 0644 deploy/agent/approved_release_agent.py \
  /usr/local/libexec/betasoft-release-agent/agent/approved_release_agent.py
sudo install -o root -g root -m 0644 deploy/portable/verify_release.py \
  /usr/local/libexec/betasoft-release-agent/portable/verify_release.py
sudo install -o root -g root -m 0644 deploy/agent/systemd/betasoft-release-agent.service \
  /etc/systemd/system/betasoft-release-agent.service
sudo install -o root -g root -m 0644 deploy/agent/systemd/betasoft-release-agent.timer \
  /etc/systemd/system/betasoft-release-agent.timer
sudo systemctl daemon-reload
sudo systemd-analyze verify betasoft-release-agent.service betasoft-release-agent.timer
sudo systemctl start betasoft-release-agent.service
sudo journalctl -u betasoft-release-agent.service -n 30 --no-pager
```

Until a release is staged, expected log is `AGENT_NO_APPROVED_RELEASE`.
Enabling the timer is optional and remains observer-only:

```bash
sudo systemctl enable --now betasoft-release-agent.timer
systemctl list-timers --all betasoft-release-agent.timer
```

The timer is weekday every five minutes. Execution has a narrower window:
08:45–17:15 Asia/Ho_Chi_Minh, keeping away from scheduled backup at 17:45
and EC2 stop at 18:30. If the host is down, `Persistent=false` ensures
no catch-up deployment.

## Preparing a reviewed pilot release — separate manual approval

1. Verify the release's GitHub workflow run completed successfully, validate
   its GHCR digest against the **independent image build**, and ensure the
   artifact came from the intended release source revision. Do not assume
   source_sha in `release.json` is the image's build source SHA.
2. Download and independently check the ZIP SHA256. Install the ZIP into the
   root-only inbox **without extracting executable scripts into the host**:
   `sudo install -o root -g root -m 0600 openproject-pilot-N.zip /etc/betasoft/approved-release/release.zip`.
3. An administrator separately writes root-owned
   `/etc/betasoft/approved-release/approval.json` with exactly:

```json
{
  "schema_version": 1,
  "environment": "pilot",
  "artifact_sha256": "<independently verified SHA256 of the exact ZIP bytes>",
  "image": "ghcr.io/aristha/openproject@sha256:<approved 64-hex digest>",
  "source_sha": "<reviewed 40-hex release source commit>",
  "schema_approved": "NO_MIGRATIONS",
  "expires_at": "2026-11-09T09:00:00+00:00"
}
```

**Example expiry is illustrative**, not valid indefinitely. Use an actual
future expiry within seven days. Ensure ownership root and permissions 0600:
`sudo chown root:root /etc/betasoft/approved-release/approval.json`
and `sudo chmod 0600 /etc/betasoft/approved-release/approval.json`.

4. Run observer manually: `sudo systemctl start betasoft-release-agent.service`.
   When approved, expected output: `AGENT_OBSERVE_ONLY verified approved release; nothing deployed`.
   Unapproved/broken/expired releases exit nonzero.

## Additional fail-closed host prerequisites (security hardening)

- Every directory component in the configured inbox and state paths must be root-owned, a real directory, and not writable by group/others. Avoid symlinks, including in ancestor components.
- The backup hook and its parent directories must be root-owned; the hook must be a regular executable file that is not writable by group/others.
- Lock and deployed-state files must be root-only. Existing state with unsafe ownership, permissions, or type is rejected.
- The release ZIP is subject to both compressed (8 MiB) and aggregate uncompressed (4 MiB) limits; oversized bundles fail without deployment.
- The deployment subprocess receives a minimal environment (PATH, HOME, LANG and explicitly documented DEPLOY_* inputs), not arbitrary inherited shell variables. If a supported deploy requires additional variables, review and explicitly add them instead of forwarding the host environment wholesale.
- These checks are code-level defense in depth. Do not enable --execute until the operator validates them on a disposable staging host and the live rollback/recovery acceptance gates are met.

## Optional execution: NOT yet approved for the pilot

**Do not enable execution for Issue #9 before Issue #6 live rollback and
Issue #5 recovery readiness/alerts are accepted.** Enabling requires:
an explicit systemd unit override to append `--execute`, and a root-only
EnvironmentFile setting `OPENPROJECT_AGENT_EXECUTE_ENABLED=YES`.
Both gates are necessary; neither is enabled by the shipped service.
The agent then invokes the vetted bundle's `deploy.sh --execute` with a
root-local backup hook, only within the weekday window. That deploy script
performs a backup before changing images, checks HTTP 200, and attempts
image-only rollback. A successful deployment writes a root-only state
record, and repeated ticks with the same ZIP SHA are no-ops.

For a real rollout, additionally require:
- deployment freeze/maintenance approval and a fresh restorable backup;
- image-build provenance review and DB schema compatibility;
- restricted host root permissions and registries;
- alerts on failed/overdue reconciliation, plus a proven live rollback;
- an authenticated GitHub→host artifact transport/promotion channel if
  truly zero-touch, merge-triggered automatic deployment is desired.

**No workflow in this PR deploys images, installs timers, uploads SSH keys,
or starts/stops the pilot EC2.**
