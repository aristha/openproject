# Beta Soft OpenProject — Source/runtime audit (phase 1)

Tracks [Issue #7](https://github.com/aristha/openproject/issues/7), [Epic #4](https://github.com/aristha/openproject/issues/4), [CI/CD issue #6](https://github.com/aristha/openproject/issues/6).

**Scope:** GitHub fork's `dev` source at audit time. This review is **static**, not a
production EC2 inspection. Priority is predictable Docker Compose upgrades,
Community Edition use and low-friction upstream synchronization.

## Verified source observations

| Area | Evidence | Finding | Risk/action |
| --- | --- | --- | --- |
| Database migration | `docker/prod/web`, lines 6, 15–18 | `MIGRATE` defaults to `false`; if true, web runs `bundle exec rake db:migrate` before Puma. | **High:** Rolling image forward without a separate migration plan may fail when schema changes. Do not enable `MIGRATE=true` simultaneously on multiple web containers; use reviewed, single-shot migration job and explicit database recovery plan. |
| Slim entrypoint | `docker/prod/entrypoint-slim.sh`, lines 1–19 | Sets jemalloc / PostgreSQL binary path, then simply `exec "$@"`. | **High:** Entrypoint does not perform preflight, backup or migrations; deployment orchestration must own those gates. |
| Worker | `docker/prod/worker`, lines 1–9 | Runs `bundle exec good_job start`; optional `--seed` path exists. | **Medium:** Stop/start and upgrades must account for in-flight background work. Never automatically run seed during release. |
| Health checks | `config/routes.rb`, lines 46–50 | Explicit `/health_check` and `/health_checks/all` routes; OkComputer engine mounted at `/health_checks`. | **High:** Use the explicit `/health_check` for portable deployment liveness checks; validate it on EC2 with actual Host/TLS settings, and separately test full dependency checks before production rollout. |
| Runtime edition | `docker/prod/Dockerfile` and `.env.example` | `OPENPROJECT_EDITION=standard` default. | **Low:** This selects standard mode, not an Enterprise license state. Do not patch entitlement logic. |
| Assets persistence | `docker/prod/Dockerfile` | `OPENPROJECT_ATTACHMENTS__STORAGE__PATH` points to `$APP_DATA_PATH/files`, with volume at `$APP_DATA_PATH`. | **High:** App and backup must agree on the actual persistent Docker volume and path. Verify `docker inspect` output on live host. |
| Image build schema | `docker/prod/setup/dump-schema.sh` | Build stage starts isolated PostgreSQL 17 and runs migrations to dump schema. | **Medium:** This is a **build-time** operation, not the production DB upgrade. Do not mistake successful image build for successful runtime migration. |
| Private runtime secret defaults | `docker/prod/Dockerfile` | Image includes documented placeholder `SECRET_KEY_BASE=OVERWRITE_ME`; GHCR workflow checks placeholders. | **High:** Runtime must override placeholder. Never log, commit or place actual production secrets in image history. |
| Enterprise promotion | Official OpenProject environment reference | `OPENPROJECT_EE__HIDE__BANNERS` and `OPENPROJECT_EE__MANAGER__VISIBLE` supported. | **Low:** Use configuration overlay from [PR #13](https://github.com/aristha/openproject/pull/13), not removal of Enterprise code or license bypass. |

Official config reference: https://www.openproject.org/docs/installation-and-operations/configuration/environment/

## Recommended follow-up implementation

### P0 — before real image upgrade

- [ ] Confirm full restored PostgreSQL + attachment backup on isolated host ([Issue #5](https://github.com/aristha/openproject/issues/5), [PR #14](https://github.com/aristha/openproject/pull/14)).
- [ ] Inspect current and candidate schemas/migration files; record compatibility decision and a documented downgrade procedure.
- [ ] Create a **separate**, single-owner migration step when migration is required; do not run migrations on every web replica.
- [ ] Confirm actual `GET /health_check` on current EC2 application, including host header and response status.
- [ ] Verify baseline `web`, `worker`, `db` service names, image/volume paths and correct Compose overlay ordering.

### P1 — after safe pilot deployment

- [ ] Add integration smoke checks for admin login, project list, work-package creation, background job and attachment upload/download.
- [ ] Check that GoodJob recovers jobs after web/worker restart and scheduled EC2 stop.
- [ ] Check external secret, TLS and Cloudflare Tunnel configuration; avoid printing env file in CI.
- [ ] Compare fork against **exact upstream commit**, not a floating upstream branch, and document changes before rebasing.
- [ ] Measure actual memory/CPU/disk and use metrics to justify optional module disabling. Removing Enterprise assets blindly is not an optimization plan.

## Safety boundary

This audit adds **no runtime changes**. Any production migration, image update,
module disabling or secrets modification requires independent approval, backup
recovery evidence, maintenance window and rollback instructions.

## Acceptance for source audit issue #7

Static source review is the first milestone; a comprehensive audit is not
complete until the live runtime, configuration and upgrade path are validated.
