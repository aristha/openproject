# Phase 6 — GitHub pilot Environment preflight (read-only)

This is the next **source-only** safety gate under Issue #9. It does not
start an Actions workflow, create or sign a GHCR image, approve a release,
connect to EC2, or enable an agent. It is intended to verify GitHub
configuration **before** the owner authorizes the first Phase-4 build.

## Metadata prerequisites

The GitHub repository must have an existing Environment named `pilot` with:

- At least one **required reviewer** (not just a description in the UI).
- **Prevent self-review** enabled.
- A deployment branch rule that is either **protected branches only**
  with the `dev` branch actually protected, or **exactly** `dev`
  explicitly allowlisted as the only custom deployment branch policy.
- No broad branch pattern, silent missing reviewer, or missing permissions.

The script queries GitHub's REST API to read metadata for the Environment
and `dev` branch, and (when applicable) custom deployment branch policies.
It exits nonzero on HTTP error, missing permissions, incomplete metadata,
unprotected branch, missing reviewers or broad branch allowance. Results
contain only booleans and policy status, never tokens or reviewer names.

The GitHub connector currently used in this chat does not expose
Environment protection endpoints directly. Therefore **the actual pilot
configuration has not yet been verified**. Passing offline CI is not proof
of live GitHub settings.

## Operator-run preflight

Provide a short-lived GitHub token permitted to READ repository Environment
configuration and branch protection metadata; this may require repository
administrative access, depending on GitHub's API access policy. Avoid
embedding a token in scripts, workflow files, or a CLI argument.

```bash
GH_TOKEN="<operator-provided-read-token>" \
  python3 deploy/portable/check_github_pilot_readiness.py
```

Prefer passing `GH_TOKEN` through a protected shell/session rather than
storing it in history. The script sends it only to fixed GitHub API GET
endpoints and refuses redirects. Do **not** add a privileged administrative
token as a repository Actions secret just to run this preflight.

Expected output: `"status": "METADATA_PRECHECK_PASS"`. If a GET returns
403/404, treat the result as **unverified**, not an environment approval.

Manual checklist following a metadata PASS:

- [ ] Confirm GitHub branch rule actually prevents unreviewed `dev`
  workflow changes and enforces required status checks.
- [ ] Confirm `pilot` required reviewers are independent of the person
  manually triggering a candidate build.
- [ ] Confirm the Phase-4 manual workflow has no push/PR trigger and only
  writes a GHCR candidate image after an explicit owner dispatch.
- [ ] Verify the GHCR package grants the workflow the minimum package write
  permissions; no token scopes expanded to all packages.
- [ ] Obtain approval for the **registry write** before first signed image
  build. Merging workflow files is not permission to run the build.
- [ ] Execute the Phase-4 workflow only after approval and collect the
  actual immutable digest, build SHA, attestation and run evidence.
- [ ] Execute Phase-5 read-only acceptance using the exact digest/SHA;
  compare real Cosign verification against source/build policy.
- [ ] Test external alert provider delivery/ACK, Issue #6 live rollback
  and Issue #5 recovery before any EC2 deployment or agent activation.

Offline regression suite:

```bash
python3 -m unittest discover -s deploy/portable -p 'test_github_pilot_readiness.py' -v
```

**Boundary:** This preflight checks a snapshot of GitHub settings at the
moment of its run and does not lock them. Recheck immediately before
approving an actual build and monitor later changes to environment/branch
rules. A metadata PASS is a prerequisite, not production readiness.
