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
