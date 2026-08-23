---
name: testing
description: Organize and write Zero Auth Lite tests, especially black-box HTTP route tests, feature-level tests, fixtures, and test documentation. Use when adding, moving, reviewing, or restructuring files under tests/, when application route packages change, or when deciding where a test belongs.
---

# Testing

Keep tests easy to locate from either a public URL or an application module.

## Choose the Test Boundary

- Put fully wired HTTP behavior under `tests/routes/`. Exercise the canonical
  app through HTTPX with real middleware, dependencies, lifespan, and stores.
- Put service, router-unit, schema, store, and generated OpenAPI tests under
  `tests/app/`, mirroring the owning application package when practical.
- Put reusable setup and data builders under `tests/fixtures/`.
- Do not import or re-export tests across test packages.

## Structure Route Tests

Mirror public route ownership deterministically:

1. Map every stable static URL prefix to the same directory segments.
   `/api/v1/organization/users` belongs under `tests/routes/api/v1/organization/`.
2. Stop directory mirroring at the owning route surface. Name files after the
   route module or workflow: `organization/test_users.py`, `auth/test_registration.py`.
3. Use the public segment, never a conceptual alias. Tests for `/api/v1/me`
   belong in `api/v1/me/`, not `account/` or `profile/` directories.
4. Keep cross-surface composition tests at the directory of the composer they
   exercise, such as `api/v1/test_mounting.py`.
5. Keep protocol surfaces under their canonical owner: OAuth2 routes under
   `tests/routes/oauth2/`; issuer-derived discovery paths stay in `oauth2/oidc/`.

Within a route directory, align test filenames with the application router
modules where that improves navigation. Split a generic `test_workflows.py`
when it covers multiple independently named route domains. Do not create files
named only after HTTP methods. A cross-domain file is acceptable when it tests
one explicit shared invariant or lifecycle; name that invariant directly, such
as `test_token_workflows.py`.

## Preserve Behavior While Moving Tests

- Move shared helpers to the nearest common `helpers.py`; do not duplicate
  security-sensitive token or session setup.
- Update imports without changing assertions, fixtures, markers, or HTTP paths
  unless the task explicitly changes behavior.
- Search for stale package paths after a move.
- Update `tests/routes/README.md` when the layout rule changes.
- Follow the user's requested verification scope before running tests, linters,
  type checkers, or skill validators.
