# Phase 4 — operator-triggered, signed GHCR candidate image build

## Scope and safety

This is an **opt-in source-only change**. The new
`.github/workflows/fork-build-attested-image.yml` has only a
`workflow_dispatch` trigger and rejects any ref other than `dev`.
Merging the PR does not run it. The workflow has **no SSH, EC2, Docker
Compose deploy, systemd installation, or agent execution**.

An administrator who manually dispatches the workflow from `dev` will
explicitly authorize an **image build and GHCR registry write** (not EC2).
The job runs in the `pilot` GitHub Environment; repository administrators
should configure required reviewers there before using it. If those
reviewer rules have not been configured, the environment name by itself
does NOT enforce approval.

It checks out the exact workflow `GITHUB_SHA`, builds
`docker/prod/Dockerfile`, and pushes a unique
`attested-candidate-<run_id>-<attempt>` tag to
`ghcr.io/aristha/openproject`. The build action reports the immutable
OCI digest. The job generates an SLSA v1 predicate containing that digest,
the checkout SHA, the fixed source repository and the workflow run.
Cosign signs the predicate in the same build job using GitHub's OIDC
keyless identity and uploads the signed attestation to GHCR. The same
job performs online Cosign verification and independently matches the
verified in-toto statement to the exact digest and SHA.

Buildx's own provenance metadata is complementary; it does not replace
the required **Cosign/Sigstore signature**. Do not treat a release
packaging SHA as the image build SHA.

## Actual operator acceptance (NOT performed in this PR)

1. Configure `pilot` GitHub Environment approval rules, branch policy
   and GHCR permissions. The workflow needs `packages:write` and
   `id-token:write` only in its signing job.
2. Review installed Docker Buildx/Cosign pinned action SHAs and approve
   the production Dockerfile build.
3. Manually invoke **Fork / Build and attest GHCR candidate (manual only)**
   on `dev`. Observe that it pushes a new candidate **only** to GHCR.
4. Read the actual image digest and image-build Git SHA from the job.
   Confirm `cosign verify-attestation` completed without insecurity flags
   and `SIGNED_IMAGE_PROVENANCE_VERIFIED` is in its log.
5. Independently validate the GHCR digest/SLSA predicate against a real
   registry. Test wrong digest, wrong signer, unsigned image, wrong commit
   and missing transparency-log proof before approving.
6. Create an independent root-owned Phase-3
   `image-provenance.json` **only after** reviewing actual evidence:
   `image`, `build_sha`, and
   `certificate_identity=https://github.com/aristha/openproject/.github/workflows/fork-build-attested-image.yml@refs/heads/dev`.
7. Test Phase-2 `--stage` fail-closed behavior in disposable staging
   only; do **not** turn on the Phase-1 `--execute` gate.
8. Test outbound alert receiver acknowledgement, idempotency, retry and
   recovery of undelivered notifications.
9. Finish Issue #6 live image rollback and Issue #5 application-level
   backup/restore acceptance **under separately authorized maintenance**.
10. Only then consider a separate, explicit change request for production
    installation, service timers and rollout execution gates.

## Important trust boundaries

- No image is asserted to be signed simply because this workflow file
  exists or is merged. **It must actually be run** and the resulting
  signed evidence must be checked against a real registry.
- The predicate describes the image build performed by this workflow and
  is signed by its CI OIDC identity. A compromised build runner/workflow
  or unauthorized changes to protected `dev` can make an untrustworthy
  build appear authorized; branch protection and reviewed workflow
  provenance are mandatory controls.
- Cosign certificate issuer and signer identity must be pinned; it is
  unsafe to use a broad signer identity regex or to disable transparency
  verification. Verify the actual Cosign version and trust roots.
- A non-pilot image and any image not covered by the approved digest,
  SLSA attestation, signer and reviewed build SHA must fail closed.
- Registry candidate signing does not approve release packaging,
  migrations, health checks, host deploy, rollback or production use.

All new workflow/actions and tests are reviewed by GitHub PR CI, but
mock tests cannot replace registry-level end-to-end acceptance.
