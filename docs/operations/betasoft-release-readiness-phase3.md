# OpenProject Auto Deploy — Phase 3 release readiness (Issue #9)

**Source-only. No EC2 changes, systemd activation, deployments or merges.**
Phase 1's deployment agent is still observe-only. Phase 2's ZIP transport still
does not execute containers. Phase 3 introduces two separately invoked gates:
signed image provenance verification before ZIP staging, and opt-in external
alert dispatch.

## 1. Signed image provenance gate

The Phase 2 transport now refuses `--stage` unless
`--provenance-policy /etc/betasoft/release-transport/image-provenance.json`
is explicitly provided. The policy is a **root-owned, 0600, separately
reviewed** JSON document; no operator policy is generated from CI.

Example schema (replace image, build SHA and workflow with actual reviewed
values; these placeholders are **not deployable**):

```json
{
  "schema_version": 1,
  "image": "ghcr.io/aristha/openproject@sha256:<64 lowercase hex>",
  "build_sha": "<40 lowercase hex of the IMAGE BUILD source commit>",
  "certificate_identity": "https://github.com/aristha/openproject/.github/workflows/<reviewed-build-workflow>.yml@refs/heads/dev",
  "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
  "source_repository": "aristha/openproject"
}
```

Install and review a pinned `cosign` binary separately at
`/usr/local/bin/cosign`, with Sigstore trusted roots appropriately maintained.
The verifier invokes `cosign verify-attestation --type slsaprovenance1` with
**exact** Fulcio certificate identity and OIDC issuer, requiring Cosign's
normal transparency and signature checks. It parses only successfully
cryptographically verified attestation output. It then requires a SLSA v1
in-toto subject bound to the **exact approved GHCR digest** and a resolved
GitHub repository dependency bound to the **exact independently reviewed
image-build commit SHA**. There is no `--insecure-ignore-tlog` switch.

**Important:** The release packaging workflow's `source_sha` does not prove
the OCI image build source. No image signing/attestation producer has been
installed or enabled by this PR. If the trusted build workflow has not yet
published the required attestation, staging intentionally fails closed.
The image build identity must be independently audited before operator
approval. This verifier does not claim that existing images are signed.

Example explicit staging (still **does not deploy**):

```bash
sudo python3 /usr/local/libexec/betasoft-release-agent/agent/release_transport.py \
  --stage --provenance-policy /etc/betasoft/release-transport/image-provenance.json
```

The reviewable `transport-request.json` and Phase-1 `approval.json` are
still required. All existing ZIP integrity checks stay enabled. Do not feed
Cosign an attacker-controlled signer identity or turn off log verification.

## 2. External alert delivery (optional, separate executable)

The Phase-2 failure alert spool is unchanged. Phase 3 adds
`deploy/agent/alert_dispatch.py`, a **manually invoked** dispatcher with
root-owned config, a separate read-only delivery token, exact HTTPS endpoint
hostname, blocked redirects and private/local hostnames/IP literals.

Config at `/etc/betasoft/release-transport/alert-delivery.json`:

```json
{
  "schema_version": 1,
  "endpoint": "https://<approved-notification-provider-host>/api/events",
  "expected_host": "<approved-notification-provider-host>",
  "token_file": "/etc/betasoft/release-transport/alert-bearer-token"
}
```

Create `/var/lib/betasoft-release-agent/alerts-delivered` (0700/root).
The existing `alerts` directory remains the pending queue. The transport
audit and alert spool remain separate. The provider must support a JSON POST
body and `Authorization: Bearer`; select and test the provider endpoint
manually. No endpoint, token, or systemd timer is installed by this PR.

Dispatcher behavior:
- One non-symlink 0600/root-owned JSON alert per file (maximum 16 KiB).
- Per-spool root-only `flock`; no concurrent duplicate dispatch.
- Stable SHA256 idempotency key repeated across all attempts for that file,
  included in the `Idempotency-Key` header and payload.
- At most three attempts with bounded exponential backoff for timeout,
  network errors, HTTP 408/429/5xx; permanent 4xx does not retry.
- On success (2xx), atomically moves the file to the root-owned delivered
  archive. On failure it remains queued and command exits nonzero.
- Crash after provider accepted but before local archive is moved can cause a
  duplicate on restart. **Receiver must enforce the idempotency key.**
- No retries forever, no unattended network activity, no secrets in logs.

Run only after human configuration and approval:

```bash
sudo python3 /usr/local/libexec/betasoft-release-agent/agent/alert_dispatch.py
```

This implementation delivers to a configured HTTPS endpoint but is not a
guarantee that an operator received or acknowledged the message. Monitoring
and receiver acknowledgements must be tested before operational acceptance.
Hostname allowlisting does not replace host firewall/proxy egress policy or
TLS and DNS protections.

## 3. Readiness / acceptance gates

- [x] Phase 1 observe-only reconciler and security checks on `dev`.
- [x] Phase 2 authenticated transport with independent operator approval.
- [x] Phase 3 source-only Sigstore verifier, fail-closed staging gate, alert
  delivery client and regression tests in GitHub CI.
- [ ] Build workflow publishes verifiable signed SLSA v1 attestation for exact
  GHCR image digest. Pin and review signer workflow/certificate identity.
- [ ] Run valid/invalid attestation verification **against actual registry**
  with reviewed Cosign binary and trust roots. Do not use mock tests alone as proof.
- [ ] Operator validates image build SHA separately from packaging source SHA.
- [ ] Operator provisions host root-only config and minimum-scope credentials,
  and dry-runs verify-only on a disposable staging host.
- [ ] Configure external notification provider; validate 2xx delivery,
  timeout/429 retries, dedupe, paging, acknowledgement and overdue alerts.
- [ ] Complete #6 real deploy and rollback drill plus #5 application recovery
  acceptance with fresh restorable backups and maintenance authorization.
- [ ] Security review, required checks, branch policy approvals and manual merge.
- [ ] Explicit new written authorization before installing any services,
  enabling timers or lifting execution gates on production EC2.

**Blocking policy:** Do not claim unattended auto deploy or production
readiness until every environment-specific, operational and recovery gate above
is evidenced and approved. Phase 3 code does not change Phase 1's
`--execute` or `OPENPROJECT_AGENT_EXECUTE_ENABLED` gates.
