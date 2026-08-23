# Zero Auth Lite

Zero Auth Lite is a readable FastAPI reference server for authentication and
authorization. It is a small educational identity provider: it owns users,
browser sessions, OAuth2 clients, tokens, and OpenID Connect endpoints without
trying to become a complete IAM platform.

The documentation has five sections. The first four explain how to use and
operate Zero Auth Lite. The last is for contributors working on the repository.

## Product Documentation

### Getting Started

Install the server, configure the first operator, then register and exercise an
OAuth2 client. Follow these pages in order:

1. [Installation](getting-started/installation.md)
2. [Initial configuration](getting-started/configuration.md)
3. [First OAuth2 client](getting-started/first-client.md)

### Guides

Understand and use the authentication features: [users and organizations](guides/users-and-organizations.md),
[browser sessions and CSRF](guides/sessions-and-csrf.md),
[OAuth2 flows](guides/oauth2-flows.md), and
[OpenID Connect](guides/openid-connect.md).

### Operations

Run Zero Auth Lite beyond a local first start. Begin with
[deployment](operations/deployment.md), then cover the
[database](operations/database.md), [migrations](operations/migrations.md),
[backups](operations/backups.md), [logging](operations/logging.md), and
[security](operations/security.md).

### Reference

Look up the public technical contract without following a tutorial:
[settings](reference/settings.md), [routes](reference/routes.md),
[application errors](reference/errors.md), and
[OAuth2 errors](reference/oauth2-errors.md).

## Contributor Documentation

### Development

Work on Zero Auth Lite itself. Start with the [development setup](development/setup.md)
and [repository structure](development/repository-structure.md), then use the
internal architecture, testing, migration, routing, and contribution pages in
this section.

The supported runtime is one Zero Auth Lite application node. High-availability
multi-node operation, SAML, SCIM, LDAP, social login, and enterprise IAM
features are outside the project scope.
