# Phase 5 — read-only GHCR signed provenance acceptance

The new **Fork / Verify signed GHCR candidate (read-only manual)** workflow
is an acceptance check for Issue #9. It can be run on `dev` using the digest
and image-build Git SHA from an explicitly approved Phase-4 image build.
It does NOT build, push, sign, approve, stage, deploy or change EC2.
Merging this source-only workflow does not run it.

## Reviewable procedure

1. Confirm PR #21 is merged and the approved, manually dispatched
   `Fork / Build and attest GHCR candidate (manual only)` workflow has
   **actually succeeded** for the intended image. A merge is not evidence of
   a completed build.
2. Record the *exact* immutable image digest, the exact 40-character image
   build SHA, run URL, workflow identity, signer identity and registry target.
   Do not confuse the release packaging SHA with the image build SHA.
3. Check repository GHCR package visibility and the `pilot` GitHub
   Environment reviewer rules. `environment: pilot` without reviewers is
   not itself a protected approval boundary.
4. Manually dispatch
   `.github/workflows/fork-verify-attested-image.yml` on `dev`,
   entering the digest and build SHA. The job logs in to GHCR with a
   short-lived `packages: read` token and validates live signed SLSA v1
   provenance using a pinned Cosign installer.
5. The acceptance test must pass the **positive** exact digest/source/signer
   check and reject the **negative** wrong source, wrong signer, and wrong
   image digest. No authentication bypasses or insecure transparency flags.
6. Archive the workflow run URL and verified digest/SHA in Issue #9.
   Only then prepare root-owned Phase-3 `image-provenance.json` for later
   **separately approved** staging tests on a disposable host.
7. Complete external incident alert provider delivery/acknowledgement,
   Issue #6 live rollback and Issue #5 data recovery under operator control.
   Production EC2 and the Phase-1 `--execute` gate remain unchanged.

## Threat model and test limitations

The registry-verification job is **read-only** and only runs with
`workflow_dispatch` on `dev`. It has `contents:read` and
`packages:read`, not `packages:write` or `id-token:write`, and contains
no SSH, EC2, Docker Compose or service management commands.

A success demonstrates that the signed statement's subject digest and
source Git SHA match the values supplied for that run, with the pinned signer
identity. It does not establish that the build inputs, dependencies,
workflow code or chosen Git revision were trustworthy without independent
source review and branch protection.

A negative test producing nonzero is consistent with rejection, but a
registry outage or transient network failure can also cause rejection.
The positive check must succeed first; monitor logs and repeat under known
network health if necessary. Verify provider identity, Cosign version and
actual registry policies independently.

**Do not** run the Phase-4 build automatically, approve new image digests
without human review, schedule the host agent, or enable unattended deploy.

## GitHub runner vs production Cosign executable (fix)

The `sigstore/cosign-installer` action installs Cosign into the GitHub
runner's tool directory (default under `$HOME/.cosign`), which is added
to `PATH`; it does not guarantee `/usr/local/bin/cosign`.
The manual read-only acceptance job now resolves `cosign` with
`shutil.which` and explicitly passes its absolute path to the verifier,
while retaining runner `HOME`/`DOCKER_CONFIG` required by the earlier
`docker/login-action` GHCR authentication.

The host-side release agent retains a separate default:
`/usr/local/bin/cosign`, root-owned and reviewable, with a restricted
`HOME=/root` verification process. A registry artifact or control file
cannot select an arbitrary executable path.

This change fixes a runtime compatibility issue **without dispatching**
the manual registry verification workflow. Real GHCR signature acceptance
remains outstanding until an authorized operator supplies a reviewed
candidate image digest and image-build SHA and runs the workflow.
