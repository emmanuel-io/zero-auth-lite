# Production Hardening

Zero Auth Lite exposes security decisions but is not a complete production identity
service. Review each item against the deployment's threat model and
architecture.

Set `ZA_APP__ENVIRONMENT=deployment` before exposing the server. Startup
then rejects the checked-in development secrets and signing key, missing
trusted hosts, insecure browser-session or CSRF cookies,
non-HTTPS public issuer and email URLs, malformed deployment origins, local-only
hosts in issuer, email, cookie, CORS, and CSRF settings, and disabled workflow
email delivery. It also rejects disabling both browser sessions and all OAuth2
grants. These checks catch unsafe local defaults; the rest of this checklist
still applies.

It targets prototypes, internal applications, and nominal-load deployments on
one node. This checklist hardens that deployment model; it does not
turn Zero Auth Lite into a high-availability multi-node service.

## Deployment Topology

- Run one Zero Auth Lite application node and execute Alembic before starting its
  application processes.
- Ensure every process on that node uses the same database, immutable settings,
  signing keys, hash secrets, and runtime lock directory.
- Do not infer multi-node safety from outbox leases or an external relational
  database. Node failover, rolling deployment, and
  cross-node configuration and key rollout are not supported guarantees.

## Secrets And Keys

- Replace every development hash secret with independent random values of at
  least the required length.
- Store private signing keys and client secrets outside source control.
- Define a signing-key rotation procedure and retain old public keys until
  affected tokens expire.
- Remove first-run bootstrap credentials after use.
- Rotate auth-token derivation secrets with a new key identifier and retain the
  previous identifier and secret until no stored workflow token references it.

## TLS, Hosts, And Proxies

- Terminate TLS for every credential, cookie, and token endpoint.
- Configure trusted hosts and reject unexpected `Host` headers.
- Trust forwarded headers only from known proxies.
- Keep public scheme, host, port, OIDC issuer, redirect URIs, and CSRF origins
  consistent.

## Browser Cookies And CSRF

- Keep session cookies `HttpOnly` and `Secure`.
- Choose `SameSite`, cookie domain, and trusted origins for the actual frontend
  topology.
- Require CSRF checks on cookie-authenticated state changes.
- When a browser serializes a form's `Origin` as `null`, accept it only for a
  `same-origin` document navigation identified by Fetch Metadata headers; the
  form token and cookie must still match.
- Test login, logout, subdomain, and reverse-proxy behavior in a real browser.

Built-in workflow links carry their single-use verification, invitation, or
password-reset token in the URL until the browser submits the corresponding
form. Every server-rendered page therefore sends `Referrer-Policy: same-origin`:
same-origin form submissions retain the origin signal required by CSRF checks,
while workflow URLs are not propagated to another origin through the `Referer`
header. The same pages send a restrictive Content Security Policy that permits
same-origin styles and forms while rejecting other content, framing, and
document base overrides.
Preserve these headers at the reverse proxy and keep request URLs and headers
containing workflow tokens out of access logs.

## Persistence

- Use the supported [database](database.md) configuration and apply
  [migrations](migrations.md) before application processes start.
- Define and test the [backup and recovery](backups.md) procedure for all
  durable identity, session, and token state.

## OAuth2 And OIDC

- Register exact redirect URIs and require PKCE S256 for public clients.
- Enable only the grants required by the application.
- Authenticate confidential clients and restrict their grants and scopes.
- Validate issuer, audience, expiry, signature, key ID, and persisted token
  state at resource boundaries.
- Keep access-token lifetimes short and monitor refresh-token reuse.

## Request Limiting And Edge Security

Zero Auth Lite does not implement a request limiter. That control belongs to the
deployment boundary because this project is focused on a readable, single-node,
SQLite identity provider rather than edge-security infrastructure.

- Put a trusted reverse proxy, API gateway, or equivalent control in front of
  every endpoint exposed to untrusted traffic.
- Apply stricter policies to login, registration, password recovery, email
  verification requests, administrative invitation resends, OAuth2 token and
  client-authentication failures, device authorization and verification,
  introspection, and revocation.
- Choose keys and limits for the actual topology. Source address alone may be
  unreliable behind carrier NAT, corporate proxies, or privacy relays; combine
  it with route, client identity, or another deployment-owned signal where
  appropriate.
- Decide explicitly whether a limiter outage fails open or closed, and ensure
  its generated `429` responses and retry guidance do not expose account or
  client existence.
- Trust forwarded addresses only from the proxy that enforces the policy. A
  direct path to the application must not bypass that boundary.
- Treat bot detection, fraud detection, WAF, and related controls as separate
  deployment concerns when the threat model requires them.

## Logging And Monitoring

Follow the [logging and monitoring](logging.md) guidance and keep all tokens,
secrets, and notification links out of logs.

## Unsupported Guarantees

Zero Auth Lite does not provide high availability or supported multi-node
deployment. It also does not provide disaster recovery, external secret
management, distributed tracing, managed key custody, automated key rotation,
production mail delivery, fraud detection, compliance certification, or
enterprise identity protocols. The deploying application must supply the
controls required by its threat model.
