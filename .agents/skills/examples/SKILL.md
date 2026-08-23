---
name: examples
description: Work on runnable Zero Auth Lite examples and their Docker Compose setup.
---

# Examples Skill

## Purpose

Examples are executable views of the canonical Zero Auth Lite server.

They demonstrate focused authentication concepts by selecting settings and
walking through the routes owned by `app/`.

## Principles

- Each example should be self-contained.
- Each example should focus on one concept.
- Each example should be runnable in a few minutes.
- Duplication is acceptable when it improves readability.
- Avoid clever shared infrastructure.
- Avoid cross-example dependencies.

## Recommended Example Types

Examples may include:

- sessions;
- authorization-code;
- client-credentials;
- device-code;
- oidc.

## Canonical Server Ownership

The canonical server owns:

- FastAPI app creation and settings;
- database wiring, SQLAlchemy models, repositories, and migrations;
- browser-session, OAuth2, OIDC, and identity behavior.

Example profiles may own focused environment files, walkthrough documentation,
and local stack commands. They must not duplicate or replace the canonical
identity models and protocol implementation.

## Docker Compose

Each example may include its own `compose.yaml`.

Repeated Compose services are acceptable.

Compose files are documentation that can be executed.

Prefer clarity over DRY.

## Mailpit

Mailpit is appropriate for examples involving:

- email verification;
- password reset;
- invitation-like flows.

Mailpit setup may be duplicated in each relevant example.

## Caddy And TLS

Caddy with mkcert is appropriate for examples involving:

- secure cookies;
- HTTPS redirect URIs;
- OIDC issuer URLs;
- realistic OAuth2 callbacks.

Keep Caddyfiles simple.

Do not introduce dynamic Caddy label systems.

## Non-Goals

Do not add:

- production deployment logic;
- Kubernetes;
- multi-environment setup;
- complex reverse proxy orchestration;
- shared Docker Compose layering unless absolutely necessary.
