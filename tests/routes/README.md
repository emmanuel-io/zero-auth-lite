# Route Test Layout

Use this package for fully wired HTTP tests against the canonical FastAPI app.
Exercise the app through HTTPX with real middleware, dependencies, lifespan,
and SQLAlchemy-backed persistence.

## Directory Rule

Mirror each stable public route prefix using the same directory segments:

| Public surface | Test directory |
| --- | --- |
| `/api/v1/auth/*` | `tests/routes/api/v1/auth/` |
| `/api/v1/me/*` | `tests/routes/api/v1/me/` |
| `/api/v1/organization/*` | `tests/routes/api/v1/organization/` |
| `/api/v1/admin/*` | `tests/routes/api/v1/admin/` |
| `/api/v1/sessions/*` | `tests/routes/api/v1/sessions/` |
| `/oauth2/*` | `tests/routes/oauth2/` |

Use the public segment rather than a conceptual alias: `/api/v1/me` maps to
`me/`, never `account/`. Stop adding directories at the owning route surface;
inside it, name files after the route module or tested workflow. For example,
`/api/v1/organization/users` maps to `organization/test_users.py`.

Keep cross-surface composition tests beside their composer, such as
`api/v1/test_mounting.py`. Issuer-derived `/.well-known/*` tests remain under
`oauth2/oidc/` because they belong to the OIDC protocol surface.

Do not name files after HTTP methods. Split large tests by behavior. A file may
cross route modules only when it verifies one named shared invariant or
lifecycle, such as `auth/test_token_workflows.py`.

Route tests must not import or re-export tests from another package.
Feature-level router, service, persistence, schema, validation, and OpenAPI tests stay
under `tests/app/`; shared setup belongs under `tests/fixtures/`.
