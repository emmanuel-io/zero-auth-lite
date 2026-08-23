# Compose Routers

Use this guide when adding or relocating a route. The
[composition reference](composition.md) explains the complete application
lifecycle and settings ownership; the [startup route
matrix](../reference/routes.md#startup-route-matrix) is the canonical list of
settings-driven surfaces.

## Choose the Owner

Place the handler in the feature that owns its behavior:

- application JSON contracts belong under `app/api/v1/`;
- browser-session JSON transport belongs under
  `app/api/v1/browser_sessions/` and is mounted at `/api/v1/sessions`;
- OAuth2 and OIDC protocol handlers belong under `app/oauth2/`;
- built-in authentication pages belong under `app/web/`.

Do not move standardized OAuth2 or issuer-derived OIDC routes under `/api/v1`.

## Choose the Composition Layer

Route composition has three layers:

1. A leaf module defines handlers and exports a plain `router` when its route
   surface is static.
2. A feature composer exposes `create_*_router(settings)` when settings or
   issuer-derived paths determine which leaf routers are present.
3. `app.main.create_app()` mounts only top-level feature routers, middleware,
   exception handlers, `/health`, and optional static assets.

Keep settings-driven route selection in the feature composer. Do not read
settings again inside leaf modules to decide whether a route exists.

## Add the Route

1. Define one handler for each HTTP operation in the owning leaf module.
2. Preserve typed FastAPI `Query`, `Form`, `Header`, `Cookie`, `Security`, and
   dependency parameters so runtime validation and OpenAPI stay aligned.
3. Include the leaf router through its feature composer.
4. Change `app/main.py` only when adding or removing a top-level surface.
5. Add route-level behavior tests and an OpenAPI contract test when the
   transport contract changes.

Feature flags are evaluated when `create_app()` builds the application.
Changing environment variables or replacing `app.state.settings` afterward
does not alter mounted routes; construct a new application to apply a new
settings snapshot.
