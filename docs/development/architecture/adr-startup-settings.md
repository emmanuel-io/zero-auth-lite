# Startup Settings Are an Immutable Composition

## Context

Routes, middleware, and issuer-derived paths are selected when the application
is constructed. Configuration must therefore have one owner and one stable
lifetime; reading mutable or duplicated settings after construction would make
the effective policy depend on when a value was observed.

## Decision

`Settings` is an immutable startup snapshot composed from feature sections
such as `api`, `browser_session`, `oauth2`, and `identity_workflow`, plus explicit
root operational fields including `db_path` and `db_echo`. User and organization
management, versioned identity workflows, workflow-token persistence, and the
outbox dispatcher form the server baseline. Public registration is the narrow
exception:
`identity_workflow.registration_enabled` controls whether anonymous callers can create an
organization and its initial user and request that registration email.
It requires browser sessions so a newly registered identity retains a supported
authentication and self-service path. Within an enabled interactive JSON
transport, confirmation stays available for already-issued tokens. Built-in
HTML confirmation is selected separately by the presentation mode. Invitations,
password recovery, email-change confirmation, and administrative creation also
remain available when registration is disabled. `browser_session` owns
the optional browser-authentication mechanism and its CSRF settings, while
OAuth2 owns its optional grants, OIDC, and JWKS capabilities. SQLAlchemy is the
persistence baseline.
Each section model owns the canonical defaults for its feature. The root model
assembles immutable section instances but does not redefine their values in
factories or lambdas.

`create_app()` accepts an explicit snapshot or loads one from TOML and the
environment.
Application construction uses its local snapshot to select routes and
middleware. The same snapshot is stored on `app.state` only for lifespan and
request dependencies. Changing environment variables or application state
after construction is not a supported reconfiguration mechanism; applying a
new configuration requires a new application process.

`app.environment=development` permits the repeatable local keys used by the
examples. `app.environment=deployment` is an explicit fail-fast boundary: it
rejects known local secrets and signing keys used by enabled or reachable
capabilities and requires trusted hosts, secure session and CSRF cookies, an
HTTPS public issuer, CORS origins when configured, and exact absolute HTTPS
CSRF origins. When identity workflows are reachable, it also requires an HTTPS
non-local email URL and notification delivery. The root snapshot requires
browser sessions or an OAuth2 grant in every environment so the canonical
server cannot start without an authentication mechanism, and rejects
self-registration when browser sessions are disabled. These validations do not
require the issuer and frontend to share one host. Deployment mode does not
imply high availability or replace a deployment threat-model review.

This process-local snapshot matches the supported single-node deployment model.
Zero Auth Lite does not provide a distributed configuration source, live
cross-node convergence, or coordinated key and settings rollout. Those
capabilities belong to the currently unsupported high-availability multi-node
topology.

The optional conventional file is `zero-auth-lite.toml`; `ZA_CONFIG_FILE` selects an
explicit file and fails startup when that path does not exist. Source priority
is explicit Python arguments, `ZA_*` environment variables, TOML, then model
defaults. TOML tables follow the composed model, while environment names use
Pydantic's nested delimiter, such as
`ZA_OAUTH2__AUTHORIZATION_CODE_ENABLED`. OAuth2 has
no master switch: its surface is enabled when a grant or JWKS publication is
enabled. Browser sessions and OAuth2 token states remain transactional SQL
state. A nested environment value updates only that field and preserves every
other canonical section default.

The `ui` section configures three independent presentation decisions.
`ui.identity_workflow_mode` selects built-in or external identity-workflow pages, or
disables that presentation.
The separate `api.interactive_auth_routes_enabled` setting mounts the versioned JSON
adapters for interactive sessions, identity workflows, and external OAuth2
interactions, so built-in pages and JSON clients can coexist. It does not
control the `/me`, `/organization`, or `/server` APIs.
`ui.management_authentication`
chooses built-in `/login` and `/logout` or external management presentation.
`ui.oauth2_interaction` chooses built-in pages, an external frontend backed by
`/api/v1/oauth2` interaction contracts, or disabled interaction. Device Code
accepts built-in and external interaction, but not disabled interaction.
`ui.urls` contains every browser destination consumed by these flows. Its
defaults target the built-in pages; external modes require absolute HTTP(S)
destinations, while built-in modes validate their canonical paths.
External identity or management presentation requires the interactive API
routes.
External OAuth2 presentation requires it only when an interactive grant is
enabled. Changing presentation settings leaves enabled OAuth2 and OIDC protocol
routes available. Mail, CORS,
outbox retry, and retention values are operational settings. A deployment may
disable mail only when built-in and JSON identity-workflow presentation,
browser sessions, and Refresh Token are all disabled.

Router factories are retained only where configuration changes registered
paths or version composition. `app/api/router.py` remains the API-version
boundary, while v1 always includes the identity lifecycle and conditionally
adds only routes belonging to optional authentication mechanisms.

## Consequences

Runtime composition has one stable source of truth and feature configuration is
readable by ownership. Applying environment changes requires constructing a new
application process. Tests that need another configuration must build another
settings snapshot and application rather than mutate a running app; this adds
test setup but keeps production architecture explicit.

The web lifespan performs database validation and operator bootstrap but does
not start persistent maintenance loops. Outbox delivery and OAuth2 persistence
cleanup run in explicit side processes, so their concurrency does not depend on
the number of ASGI workers.
