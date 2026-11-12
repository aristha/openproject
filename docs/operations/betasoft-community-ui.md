# Community Edition UI configuration audit — Beta Soft

Tracking: [Issue #12](https://github.com/aristha/openproject/issues/12), [Source Audit #7](https://github.com/aristha/openproject/issues/7), [Epic #4](https://github.com/aristha/openproject/issues/4).

## Findings grounded in fork and upstream

The fork's `docker/prod/Dockerfile` and `.env.example` default to
`OPENPROJECT_EDITION=standard`. This is a mode selection (standard vs. BIM),
**not** a license bypass. Enterprise on-premises add-ons require a valid
subscription/token, per official OpenProject documentation.

OpenProject officially exposes:
- `OPENPROJECT_EE__HIDE__BANNERS=true` to hide Enterprise upsell banners.
- `OPENPROJECT_EE__MANAGER__VISIBLE=false` to hide the Enterprise configuration page.
- `OPENPROJECT_DISABLED__MODULES` to disable named application modules, not to
  uninstall Enterprise code. Do not use this as a blanket switch.
- `OPENPROJECT_SHOW__COMMUNITY__LINKS=false` only if hiding community links is
  desired; this is NOT required to turn off paid-feature promotion.

Source:
- https://www.openproject.org/docs/installation-and-operations/configuration/environment/
- https://www.openproject.org/docs/installation-and-operations/configuration/
- https://www.openproject.org/docs/enterprise-guide/enterprise-on-premises-guide/activate-enterprise-on-premises/

The current pilot's live token state and effective runtime environment **have not
been inspected**. No assertion is made that a paid subscription exists or that
individual Enterprise features are consuming resources.

## Recommendation

Use `deploy/overlays/compose.community-ui.example.yaml` as an optional,
non-destructive operator-controlled overlay if the two EE promotional settings
are desired. Keep Enterprise entitlement checks and bundled upstream modules
unchanged. Avoid editing Rails/Angular licensing checks, CSS removal hacks and
deleting assets: those approaches increase merge friction and can invalidate
security/upgrade assumptions.

Do not disable authentication, 2FA, audit features or security update warnings
as a side-effect.

## Safe rollout — NOT executed by this PR

1. Confirm pilot is on a planned maintenance window and save the current
   effective Compose configuration *without publishing secrets*.
2. Inspect the effective container environment locally, printing only
   `OPENPROJECT_EDITION`, `OPENPROJECT_EE__HIDE__BANNERS` and
   `OPENPROJECT_EE__MANAGER__VISIBLE`, **not** all environment variables.
3. Audit the Enterprise page as an admin without pasting token values.
4. Copy this example overlay outside the application source into the host's
   protected deployment directory.
5. Validate with `docker compose -f compose.yaml -f compose.community-ui.yaml config --quiet`.
   If the host already uses `compose.deploy.yaml`, include **both** overlays
   in every Compose command, with deploy image override last.
6. Under a scheduled maintenance/approval window, update only `web` and
   `worker`, and verify the login page, projects, work packages and
   administrator menu.
7. To revert, remove this overlay from subsequent Compose invocations and
   re-create only `web` and `worker`. Keep any image override applied.

## Operational acceptance

- No modification to DB schema, S3, secrets, license/token validity or
  OpenProject proprietary controls.
- Normal Community project/task/attachment functionality continues working.
- EE promotional banners and management entry are hidden as expected on
  actual deployed build.
- Rollback instructions are tested before closing Issue #12.

## Backup/restore dependency

[Issue #5](https://github.com/aristha/openproject/issues/5) remains P0.
An S3 file upload and `pg_restore --list` do not prove full recovery;
perform a restore drill in an isolated database/attachment volume before
considering automated deployment production-ready. No restoration is performed
by this documentation change.
