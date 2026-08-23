# Composition Reference

The canonical server has one supported application entry point:
`create_app()`.

## Server Composition

::: app.main.create_app

`create_app()` builds the FastAPI authentication server from an optional,
explicit `Settings` instance or loads one from the environment,
attaches stable server state such as settings and password hashing to
`app.state`, always mounts the identity-management baseline, and includes the
configured authentication and protocol surfaces.
The settings snapshot is selected during construction. `app.state.settings` is
a read-only inspection alias; replacing it is unsupported and does not change
the private snapshot used by dependencies, lifecycle setup, middleware, route
composition, or OpenAPI generation. Restart the server to apply configuration
changes.

Settings are grouped by ownership under `app`, `cors`, `oauth2`, `auth`,
`events`, `bootstrap`, `mail`, `session`, and `ui`. Database location and SQL
echo remain explicit root fields (`db_path` and `db_echo`), alongside
`runtime_dir`, `snowflake_node_id`, and `default_redirect_url`.
User and organization management, auth-token workflows, and the outbox
are server capabilities. `auth.registration_enabled` controls public
organization-and-user signup and new verification requests. Confirmation of an
already-issued verification token remains available; invitations, password
recovery, email changes, and administrative onboarding also remain available.
`ui.authentication` selects built-in authentication forms (`builtin`) or the
external JSON transport (`external`). In external mode,
`ui.external_login_url` is the browser login destination; OAuth2 continuation
identifiers are appended to it. `ui.oauth2_interaction` separately controls
OAuth2 consent and device presentation. SMTP, CORS, retry, and retention
settings are operational controls rather than feature switches. The root
settings model assembles these immutable sections and root operational fields,
so a partial nested environment override does not rebuild a section
from a second set of defaults. The OAuth2 protocol surface is enabled by a
grant or JWKS publication. Application-owned client, authorization, and token
session administration requires at least one enabled grant.
The route reference owns the complete
[startup route matrix](../reference/routes.md#startup-route-matrix).

The built-in authentication UI is enabled by default so a fresh server is
usable without developing or deploying a separate frontend.

`main.py` mounts only the top-level server surfaces: `/oauth2`, `/api`,
`/health`, and the optional built-in web router. Versioned application-owned
API contracts, including browser-session transport, are assembled by
`app/api/router.py`, which owns the inclusion of `/v1` and future API versions.
Standardized OAuth2 and OIDC endpoints remain outside that application API
boundary.

Route composition follows three layers:

- Leaf routers define endpoint handlers and export a plain `router`.
- Feature composers assemble settings-driven route groups such as the OAuth2
  and OIDC surface.
- `create_app()` mounts only feature-level routers plus app-global middleware
  and exception handlers.

Use a plain `router` when a module's route surface is static. Use a
`create_*_router(settings)` factory when feature flags or issuer-derived paths
change which routes exist. Settings-driven route selection belongs in feature
composition, not in leaf endpoint modules.

## Relational Service Composition

Service dependencies live beside their feature and receive the request-scoped
SQLAlchemy session directly. Browser-session services are not created when
`session.enabled` is false. OAuth2 session state is independent and remains
available to machine-to-machine grants.

## Request Context

Relational dependencies open request-scoped SQLAlchemy sessions. The DB
dependency commits pending work on normal exit, rolls back when an exception
reaches the request boundary, and does not run as application middleware.
Domain services may explicitly commit a complete multi-write workflow.
Notification events join that transaction as outbox rows and are delivered
afterward by a dedicated outbox worker. The ASGI lifespan does not run the
dispatcher, so increasing the number of web workers does not implicitly
increase delivery concurrency. See [Run the outbox
worker](../operations/outbox-worker.md).

OAuth2 persistence cleanup does not run in the ASGI lifespan. A dedicated
worker or one-shot scheduled command removes expired protocol state without
starting one scheduler per web worker. See
[Run OAuth2 persistence cleanup](../operations/oauth2-cleanup.md).

## Lifecycle

Construct the server through `create_app()`. Feature routes live in their
feature folders, and feature-level composition factories translate one
`Settings` snapshot into the mounted route surface. Restart the process to
apply a new snapshot.
