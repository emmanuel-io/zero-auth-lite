# OAuth2 Route Tests

This subtree holds fully wired HTTP tests for OAuth2 and OIDC endpoints.
Test functions are defined here and run against the canonical FastAPI lifespan;
route modules must not re-export tests from `tests/app/`.

Layout rules:

- Group browser authorization flows under `authorization/`.
- Group device-code flow coverage under `devices/`.
- Group OAuth2 and OpenID Connect discovery plus JWKS under `oidc/`, including
  issuer-derived `/.well-known/*` routes.
- Group token-endpoint behavior under `tokens/`, including client credentials,
  refresh tokens, introspection, revocation, and bearer authentication.
- Split further only when one file becomes hard to scan or mixes unrelated
  behaviors.

This structure follows the protocol surface rather than Python implementation
modules. Lower-level router, service, persistence, validation, OpenAPI, and protocol
boundary tests remain under `tests/app/oauth2/`.
