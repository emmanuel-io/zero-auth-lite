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

Settings are grouped by ownership under `app`, `api`, `cors`, `oauth2`,
`identity_workflow`, `notification_outbox`, `bootstrap`, `mail`,
`browser_session`, and `ui`. Database
location and SQL echo remain explicit root fields (`db_path` and `db_echo`),
alongside `runtime_dir` and `default_redirect_url`.
User and organization management, workflow-token lifecycle, and the outbox
are server capabilities. `api.interactive_auth_routes_enabled` mounts the versioned
JSON adapters for interactive sessions, identity workflows, and external OAuth2
interactions. It does not control `/me`, `/organization`, or `/server`. The
versioned browser-session adapter also requires `browser_session.enabled`.
`ui.identity_workflow_mode` independently selects built-in or external
identity-workflow presentation, or disables that presentation.
`identity_workflow.registration_enabled` controls
public organization-and-user signup and new verification requests, and requires
the browser-session authentication mechanism. Within an enabled interactive
JSON transport, confirmation of an already-issued verification token remains
available; invitations, password recovery, email changes, and administrative
onboarding also remain available. Built-in HTML confirmation is selected
separately by the presentation mode.
`ui.management_authentication` independently selects built-in or external
management login/logout navigation. `ui.oauth2_interaction` selects built-in,
external, or disabled OAuth2 login, consent, and Device Code presentation.
All navigation and notification destinations come from `ui.urls`; its defaults
target the built-in pages, and startup validation keeps those URLs consistent
with the selected presentation modes.
External OAuth2 interaction is implemented by versioned JSON adapters while
the server retains transaction state and authorization decisions. SMTP, CORS,
retry, and retention settings are operational controls. Mail may be disabled in
a deployment only when built-in and JSON identity-workflow presentation,
browser sessions, and Refresh Token are all disabled. The root settings model
assembles these immutable sections and root operational fields, so a partial
nested environment override does not rebuild a section from a second set of
defaults. The OAuth2 protocol surface is enabled by a grant or JWKS
publication. Application-owned client and token-session administration requires
at least one enabled grant.
The route reference owns the complete
[startup route matrix](../reference/routes.md#startup-route-matrix).

The built-in authentication UI is enabled by default so a fresh server is
usable without developing or deploying a separate frontend.

`main.py` mounts only the top-level server surfaces: `/oauth2`, `/api`,
`/health/*`, and the settings-driven web router. The web router keeps native
authentication forms on their protocol and workflow paths and groups all
session-backed HTML management pages below `/management`. Versioned application-owned
API contracts, including browser-session transport, are assembled by
`app/api/router.py`, which owns the inclusion of `/v1` and future API versions.
Standardized OAuth2 and OIDC endpoints remain outside that application API
boundary.

`app/openapi.py` is the global OpenAPI composition boundary invoked by
`create_app()`. It applies generic response transformations from
`app/core/openapi.py`, protocol-route transformations from
`app/oauth2/openapi.py`, and application API security policy from
`app/security/openapi.py`. Feature modules own their transformations; the root
orchestrator only orders and combines them.

Route composition follows three layers:

- Leaf routers define endpoint handlers and export a plain `router`.
- Feature composers assemble settings-driven route groups such as the OAuth2
  and OIDC surface.
- `create_app()` mounts only feature-level routers plus app-global middleware
  and exception handlers, then delegates OpenAPI composition to `app/openapi.py`.

Use a plain `router` when a module's route surface is static. Use a
`create_*_router(settings)` factory when feature flags or issuer-derived paths
change which routes exist. Settings-driven route selection belongs in feature
composition, not in leaf endpoint modules.

## Relational Service Composition

Service dependencies live beside their feature and receive the request-scoped
SQLAlchemy session directly. Browser-session services are not created when
`browser_session.enabled` is false. OAuth2 session state is independent and remains
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

Browser-session cleanup follows the same process boundary. Its dedicated worker
deletes bounded batches of expired or revoked rows without turning the ASGI
worker count into a scheduler count. See [Run browser-session
cleanup](../operations/browser-session-cleanup.md).

## Lifecycle

Construct the server through `create_app()`. Feature routes live in their
feature folders, and feature-level composition factories translate one
`Settings` snapshot into the mounted route surface. Restart the process to
apply a new snapshot.
