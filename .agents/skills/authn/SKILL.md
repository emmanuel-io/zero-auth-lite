---
name: authn
description: Work on authentication flows such as login, logout, sessions, email verification, and password reset.
---

# AuthN Skill

## Purpose

Authentication answers:

Who are you?

Zero Auth Lite should make authentication flows clear, testable, and easy to follow.

## Concepts

AuthN may include:

- login;
- logout;
- sessions;
- password hashing;
- email verification;
- password reset;
- secure cookies;
- refresh tokens;
- user lifecycle states.

## Principles

- Keep authentication separate from authorization.
- Make session behavior explicit.
- Make token lifecycle explicit.
- Avoid mixing user management concerns with OAuth2 grant logic.
- Do not add unnecessary enterprise identity features.

## Route Ownership

- Keep app-owned auth contracts under versioned API mounts such as
  `/api/v1/auth`.
- Keep browser-session transport mechanics such as login, logout, and CSRF
  under the versioned `/api/v1/sessions` application API contract.
- Let `app/browser_sessions/` own session behavior and services,
  `app/api/v1/browser_sessions/` own the JSON transport handlers, and
  `app/api/v1/router.py` own their versioned route composition.
- Keep OAuth2 and OIDC protocol endpoints under `/oauth2`.

## Email Handling

Examples may use Mailpit for local development.

The package may define email-related protocols.

Production email integrations are not part of the core scope.

Do not add SendGrid, Mailgun, SES, Resend, Postmark, or SMTP provider-specific logic to the package.

## Documentation Requirements

Authentication docs should explain:

- how sessions work;
- why secure cookies matter;
- when email verification is required;
- how password reset tokens differ from access tokens;
- where authentication happens before OAuth2 authorization code issuance.

## Non-Goals

Do not add:

- social login;
- LDAP;
- SCIM;
- SAML;
- full account management platform features.
