# GHCR signed candidate run #42541224602 — verifier compatibility incident

Run: https://github.com/aristha/openproject/actions/runs/42541224602

## Confirmed in job logs

- Build/push: SUCCESS.
- Cosign v3.0.3 installation: SUCCESS.
- SLSA v1 predicate: generated.
- Keyless attestation signing: SUCCESS.
- `cosign verify-attestation`: exit 0; Cosign reports claim, transparency
  log and certificate verification.
- Python `check_verified_build_attestation.py`: FAIL with
  `SIGNED_IMAGE_PROVENANCE_REJECTED` (no traceback or decoded payload in
  the original logs).

Image is already present in GHCR:
`ghcr.io/aristha/openproject@sha256:d3fbb478c6e7fd8c6f1201a42904aad512510ca062a8cb7ef207bbe38220ebcd`
Source SHA: `d9ce44000e50562af43eac44efe6dc172cd39e48`.

Do **not** redeploy or re-sign automatically. A successful Cosign exit
does **not** mean application-specific SHA, builder and subject binding
are accepted. Image remains an **unapproved candidate**.

## Fix and validation plan

The previous Python parser only handled JSON records with a base64
`payload` containing an already-decoded in-toto statement. The parser
now also unwraps the in-toto DSSE envelope form before comparing the
actual SLSA statement. It rejects other payload types, malformed inner
payloads, unexpected image subjects and wrong source Git SHAs.
It continues to require successful cryptographic verification by Cosign,
and does not parse arbitrary registry JSON directly.

**Important:** The original verified JSON was redirected to a temporary
file and removed at the end of the failed runner job. The precise
Cosign v3 output shape has **not** been independently recovered; this
compatibility change is a hypothesis supported by the DSSE structure,
not yet proven against that historical image.

After this PR merges:

1. Use the existing **read-only manual** `Fork / Verify signed GHCR
   candidate` workflow on `dev`; do **not** start another build.
2. Set `image_digest` to
   `sha256:d3fbb478c6e7fd8c6f1201a42904aad512510ca062a8cb7ef207bbe38220ebcd`.
3. Set `build_sha` to
   `d9ce44000e50562af43eac44efe6dc172cd39e48`.
4. Review the positive binding and negative wrong source, signer and
   image digest checks. If it rejects, preserve minimal sanitized output
   schema before modifying verification again; never skip signature
   verification or weaken the trusted identity.
5. Record the read-only run URL and final result in Issue #9.

A successful read-only verification does not authorize EC2 deployment.
The `pilot` environment/branch controls, alert acknowledgment, rollback
rehearsal (#6) and application DR (#5, currently paused by owner) remain
separate release gates.

## Phase 10 — Read-only verification run #42619905010

The operator ran [read-only acceptance #42619905010](https://github.com/aristha/openproject/actions/runs/42619905010)
on `dev` at commit `757dc5f99fa089586b9019b8d72d454c5bb36d0c`,
with the same immutable image digest and build source SHA. GitHub logs show:

- [x] Offline negative tests passed.
- [x] GHCR read-only login passed.
- [x] Cosign v3.0.3 installation passed.
- [ ] `Verify real GHCR image and deliberately reject invalid identities`
  exited 1, but logged only `GHCR_SIGNED_PROVENANCE_ACCEPTANCE_FAILED`.
  We cannot yet distinguish cryptographic failure, statement mismatch,
  verifier output shape or a negative-control failure.

The follow-up repair adds **bounded static stage/error codes**, never raw
Cosign output, exception messages, tokens or untrusted attestation JSON.
`stage=positive code=COSIGN_CRYPTO_REJECTED` means the Cosign verification
process rejected the signature/identity/registry content; the cryptographic
or registry root cause still requires read-only investigation.
`stage=positive code=VERIFIED_STATEMENT_POLICY_REJECTED` means Cosign
returned success but Python rejected a signed statement against the exact
image/source policy. In that case only a small allowlisted set of JSON field
**names** is shown as `schema=...`. The other stages are
`negative_source`, `negative_signer` and `negative_digest`; all
unexpected success in a negative test remains a hard failure.
An unavailable executable or timeout gets `COSIGN_EXECUTION_ERROR`.

After merge, rerun **only the read-only verifier** with the **same** digest
and source SHA, then inspect its new static diagnostic. Do not re-build,
push, re-sign or deploy the existing candidate. A failing acceptance remains
a production-release blocker.

## Phase 11 — Run #42626319539 (2026-11-09)

[Read-only verify run #2](https://github.com/aristha/openproject/actions/runs/42626319539)
at `a088668468d98fdb9cad69c8af65301b2672a43c` failed in
positive statement acceptance. This time the static output confirmed:

```text
GHCR_SIGNED_PROVENANCE_ACCEPTANCE_FAILED stage=positive code=VERIFIED_STATEMENT_POLICY_REJECTED schema=keys:payload,payloadType
```

Cosign exited successfully before the Python policy rejection.
This confirms the top-level fields include `payloadType` and `payload`,
but **does not** prove the payload has the expected predicate, subject, or
source binding. The previous parser already attempted to decode
`entry["payload"]`; the exact statement mismatch remains unknown.

The follow-up adds explicit strict top-level DSSE payload type validation,
tests for the observed shape, and a non-sensitive allowlisted cause code:
`PAYLOAD_DECODE`, `STATEMENT_TYPE`, `PREDICATE_TYPE`,
`SUBJECT_OR_DIGEST`, or `SOURCE_DEPENDENCY` (among others).
Never print signed payload, GHCR credentials or arbitrary exception text.
On a successful read-only rerun, retain the original fail-closed binding
checks and do not infer automatic deployment authorization.

Use existing `image_digest=sha256:d3fbb478c6e7fd8c6f1201a42904aad512510ca062a8cb7ef207bbe38220ebcd`
and `build_sha=d9ce44000e50562af43eac44efe6dc172cd39e48`.
Do not build/push a replacement image solely to diagnose this bug.

## Phase 12 — Read-only verify run #42727654369 (2026-11-10)

[Manual run #3](https://github.com/aristha/openproject/actions/runs/42727654369)
on `dev` at merge `ad498cc9271ed12786a4947ed0467b6e7f4bdb44`
failed with:
`stage=positive code=VERIFIED_STATEMENT_POLICY_REJECTED schema=STATEMENT_TYPE`.

The verified payload decoded as a JSON statement but failed the Python
`_type` check. Cosign's own verified process had exited successfully.
The parser previously allowed only `https://in-toto.io/Statement/v1`.
However, the in-toto specification and Cosign 3 SLSA v1 examples use
`https://in-toto.io/Statement/v0.1` independently of
`predicateType=https://slsa.dev/provenance/v1`.
References:
- https://github.com/in-toto/attestation/blob/main/spec/v0.1.0/README.md
- https://docs.sigstore.dev/cosign/verifying/attestation/
- https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/slsa_level_3/decisions/006_signing_with_sbom_and_provenance_in_oci/

The parser now allows exactly those two recognized in-toto Statement
versions (`v0.1` and `v1`) and **does not** relax the required SLSA
predicate type, image name/digest, source repository/build commit, or
prior Cosign certificate/issuer/transparency verification. Offline tests
cover accepted v0.1 and fail-closed unknown statement version, wrong
source commit and wrong image digest. The candidate image remains
**unapproved** until a real read-only acceptance run passes, including
negative controls.

After the PR merges, manually rerun the read-only verification workflow
with the same existing image digest and source SHA; do not rebuild, push,
redeploy or turn on the auto-execution gate.
