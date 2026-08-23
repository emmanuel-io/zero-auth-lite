---
name: authz
description: Work on authorization concepts such as roles, permissions, scopes, organizations, and access decisions.
---

# AuthZ Skill

## Purpose

Authorization answers:

What are you allowed to do?

Zero Auth Lite should clearly separate authentication from authorization.

## Concepts

AuthZ may include:

- roles;
- permissions;
- scopes;
- organization-aware access;
- resource ownership;
- access checks;
- policy-like decisions;
- OAuth2 scopes.

## Principles

- Do not confuse AuthN and AuthZ.
- Keep access decisions explicit.
- Prefer readable permission checks over clever policy engines.
- Keep the first version simple.
- Avoid building a full authorization platform.

## Organization Model

Zero Auth Lite may assume that users and organizations have:

- a private internal ID;
- a public external ID.

Feature modules may define protocols or contracts for identity objects.

Concrete database models belong to the canonical server under `app/identity/`.

## Documentation Requirements

Authorization docs should explain:

- roles vs permissions;
- permissions vs OAuth2 scopes;
- organization access;
- resource ownership;
- why authorization must happen after authentication;
- where authorization is enforced in FastAPI.

## Non-Goals

Do not add:

- full policy engine;
- OpenFGA clone;
- OPA clone;
- complex ABAC system;
- enterprise permission administration.
