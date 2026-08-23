---
name: documentation
description: Write documentation that makes OAuth2, OIDC, AuthN, and AuthZ understandable.
---

# Documentation Skill

## Purpose

Zero Auth Lite documentation should make authentication and authorization understandable.

The documentation is as important as the code.

## Tone

Use clear, direct language.

Avoid marketing language.

Avoid pretending Zero Auth Lite is an enterprise platform.

Prefer:

- readable;
- explicit;
- understandable;
- reusable;
- reference implementation.

Avoid:

- enterprise-ready;
- production-grade IAM;
- next-generation identity platform;
- Auth0 replacement;
- Keycloak alternative.

## Documentation Goals

Every major concept should answer:

- why does this exist?
- what problem does it solve?
- who participates?
- what happens first?
- what is trusted?
- what is not trusted?
- what are common mistakes?

## Current-State Documentation

Document the product as it exists in the current checkout.

For an unpublished project:

- do not preserve changelog-style explanations of removed features;
- do not mention retired routes, settings, stores, permissions, or schemas;
- do not add migration or compatibility guidance for versions that were never
  released;
- update examples, references, navigation, and architecture descriptions so
  they form one coherent current contract;
- keep historical context only when it is necessary to explain a current
  security decision or an accepted ADR.

Tests and documentation should name supported behavior directly. Do not frame
current contracts as the absence of a feature that no published version
provided.

## OAuth2 Documentation

For each OAuth2 flow, explain:

- the actors;
- the steps;
- where authentication happens;
- what the client receives;
- what the client never sees;
- why the flow exists.

## OIDC Documentation

Explain:

- what OAuth2 does;
- what OIDC adds;
- what an ID token is;
- what UserInfo is for;
- why JWKS exists;
- how discovery works.

## Examples Documentation

Each example README should include:

- what the example demonstrates;
- how to run it;
- which URLs to open;
- which environment variables matter;
- what to look at in the code;
- what is intentionally omitted.

## Non-Goals

Do not document omitted production concerns as if they are implemented.

When something is intentionally omitted, say so clearly.
