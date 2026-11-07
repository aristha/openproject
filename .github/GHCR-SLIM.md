# Fork production image

After review and merge into `dev` (the default branch), run manually:

```sh
gh workflow run fork-ghcr-slim.yml --repo aristha/openproject --ref dev
gh run list --repo aristha/openproject --workflow fork-ghcr-slim.yml
gh run view RUN_ID --repo aristha/openproject --log-failed
```

The workflow builds `docker/prod/Dockerfile`, target `slim`, for `linux/amd64`
on standard `ubuntu-24.04`. It publishes only
`ghcr.io/aristha/openproject:sha-<full-dispatched-commit-SHA>` using the job's
`GITHUB_TOKEN`, with `contents: read` and `packages: write`. No PAT, AWS
credentials, deployment, push trigger, release tags or floating tags are used.
Only this repository's `dev` branch may publish. Third-party actions are pinned
to verified commit SHAs; checkout does not persist credentials.

An existing SHA tag is reused without building or pushing. Registry failures
other than a manifest 404 stop the job. Concurrent runs for the same commit are
serialized. This protects this workflow's tags; GHCR package write access still
allows other authorized clients to replace them, so consume the reported digest.
If a package already exists without repository access, grant this repository
Actions access in the package settings rather than adding a broader token.

The job summary records the tag, verified manifest/index digest, compressed
linux/amd64 layer size and build result. An existing tag reports its existing
digest and size. Failed builds have no new verified digest or size; inspect
the failing step and BuildKit build record. Build records can contain source
and build logs, so do not add secrets to build arguments or the context.

`SecretsUsedInArgOrEnv` is the only skipped Dockerfile rule: upstream deliberately
sets `SECRET_KEY_BASE=OVERWRITE_ME` and an empty Hocuspocus secret. All other
Dockerfile checks, including the dedicated check step, remain enabled. A preflight
policy rejects changed/extra credential-like ARG/ENV declarations and workflow
build arguments/secret inputs. Real credentials must be supplied at runtime.
After publishing (or reusing) a digest, pinned Trivy scans the image filesystem
and image configuration/history for embedded secrets. Findings fail the run;
the JSON report is private to the ephemeral runner
and removed without printing or uploading it. This is detection, not proof that
every possible credential is absent; a failed scan does not retract a published
tag. Investigate and rotate any real credential before anyone consumes that image.

## Build requirements and resource limits

Use a clean full checkout as the build context, not a local development tree.
The Dockerfile installs Ruby 4.0.9, Node 24.22.1 and npm 11.19.0, installs the
production bundle, compiles assets with a temporary build-only key and `nulldb`,
then starts a temporary PostgreSQL 17 instance inside the build stage to migrate
and dump the schema. It stops and removes that temporary cluster before pruning
source-only files for `slim`. No external database or EC2 compiler is needed.
The source's default BIM support
build argument remains unchanged. The upstream runtime `SECRET_KEY_BASE`
placeholder must be replaced at deployment time; this workflow does not deploy.

The standard public-repository Linux runner currently provides 4 CPUs, 16 GB
RAM and 14 GB advertised SSD storage. Actual free disk is checked at runtime;
the build stops below 12 GiB. BuildKit runs at most two build vertices in
parallel. This does not override the setup scripts' hardcoded Bundler jobs=8
or npm JOBS=8; setting only BUNDLE_JOBS would not reduce that concurrency.
The production frontend build has a 4096 MiB Node heap. Cold-build suitability
is unverified until the first manual run. Before/after resource logs are not a
measurement of peak RAM or peak disk usage.

If a standard runner fails:

1. Identify the actual failed layer and resource evidence: ENOSPC, exit 137/OOM,
   registry/authentication failure, network error or dependency/compiler error.
2. For ENOSPC, review measured build-layer/context size. Consider a separate,
   reviewed build-only cleanup of unused runner tooling, or reduce intermediate
   image layers/copy duplication. Do not delete source or change release tags.
3. For memory pressure, propose a separate reviewed change exposing build-only
   concurrency arguments in the Docker setup scripts, preserving existing
   defaults; then run with lower Bundler/Angular workers. Host environment
   variables are not automatically available to Dockerfile RUN instructions.
4. For dependency/network failures, fix the specific pin, repository or network
   issue without disabling TLS verification.
5. Retry manually after review. Do not switch automatically to paid runners,
   alter application behavior, or move compilation to EC2.

GitHub requires a dispatch workflow to exist on the default branch before it
can run. A PR-only workflow therefore has no genuine build result, digest or
image size yet. Merge remains a human review decision.
