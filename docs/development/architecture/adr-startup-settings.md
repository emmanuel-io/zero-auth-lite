# Startup Settings Are an Immutable Composition

## Context

Routes, middleware, and issuer-derived paths are selected when the application
is constructed. Configuration must therefore have one owner and one stable
lifetime; reading mutable or duplicated settings after construction would make
the effective policy depend on when a value was observed.

## Decision

`Settings` is an immutable startup snapshot composed from feature sections
such as `session`, `oauth2`, and `auth`, plus explicit root operational fields
including `db_path` and `db_echo`. User and organization management,
versioned identity workflows, auth-token persistence, and the outbox dispatcher
form the server baseline. Public registration is the narrow exception:
`auth.registration_enabled` controls whether anonymous callers can create an
organization and its initial user and request that registration email.
Confirmation stays available for already-issued tokens. Invitations, password
recovery, email-change confirmation, and administrative creation also remain
available when registration is disabled. `session` owns
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
rejects those known local secrets and signing keys and requires trusted hosts,
secure session and CSRF
cookies, HTTPS public issuer and email URLs, exact absolute CORS and CSRF
origins, non-local issuer, email, cookie, CORS, and CSRF hosts, and notification
delivery. The root snapshot also requires browser sessions or an OAuth2 grant
in every environment so the canonical server cannot start without an
authentication mechanism. These validations do not require the issuer and
frontend to share one host. Deployment mode does not imply high availability
or replace a deployment threat-model review.

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
enabled. Browser sessions and OAuth2 token pairs remain transactional SQL
state. A nested environment value updates only that field and preserves every
other canonical section default.

The `ui` section configures two independent presentation surfaces.
`ui.authentication=builtin` mounts the server login and authentication-email
pages. `ui.authentication=external` redirects browser authentication to
`ui.external_login_url` instead. Separately,
`ui.oauth2_interaction=builtin` mounts the consent and device-verification
pages. Setting it to `disabled` removes those interaction pages and denies
authorization requests that require login or consent; it does not delegate
interaction to API clients. Device Code is invalid in this mode because its
verification step requires the built-in interaction UI.
Changing either presentation setting leaves the versioned APIs and OAuth2 and
OIDC protocol routes available. Mail, CORS, outbox retry, and retention values
are operational settings rather than feature enablement for the permanent
baseline.

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
