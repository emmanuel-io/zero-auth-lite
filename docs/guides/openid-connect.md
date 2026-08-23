# OpenID Connect

OAuth2 grants access. It does not by itself define a standard login identity.
OpenID Connect adds identity semantics on top of the authorization code flow.

## ID Tokens

An ID token is a signed statement from the issuer to the OAuth2 client about
the authenticated user. Important claims include issuer (`iss`), subject
(`sub`), audience (`aud`), issue time, and expiry.

The client validates the signature, issuer, audience, and expiry. An ID token
is not an API access token and should not be sent to resource endpoints as one.
Zero Auth Lite issues one only when `openid` was granted. It preserves `nonce`,
uses the configured issuer and client audience, and includes a `kid` that
resolves in JWKS.

## UserInfo

UserInfo returns current identity claims for the subject represented by a valid
access token. It is useful when the client needs claims after the original ID
token was issued. The endpoint must still validate token, session, client, and
identity state.

Both GET and POST require Bearer authentication and the `openid` scope.
`openid` always permits `sub`; `profile` permits name claims; and `email`
permits `email` and `email_verified`. Unavailable or unauthorized optional
claims are omitted rather than returned as `null`.

## JWKS

The JWKS endpoint publishes public verification keys. Clients select a key by
key ID and verify signatures without receiving the private signing key. During
rotation, old public keys may need to remain published until all tokens signed
with them expire.

## Discovery

OIDC discovery publishes issuer metadata, endpoint URLs, supported response
types, token endpoint authentication methods, claims, and signing algorithms.
The issuer in discovery must exactly match the issuer in ID tokens and the
issuer expected by clients. `claims_supported` lists claims that the provider
can emit across ID tokens and UserInfo; it does not mean that every claim is
present in every response. Protocol claims such as `auth_time` and optional
`nonce` belong to ID tokens, while `profile` and `email` control the optional
identity claims.

## Zero Auth Lite Behavior

`OAuth2Settings` enables OIDC and JWKS by default. OIDC also requires both the
authorization-code grant and JWKS publication to remain enabled. The explicit
`OAuth2Settings.disabled()` configuration turns off every OAuth2 and OIDC
protocol feature. With the defaults, the canonical application exposes:

- the issuer-derived `/.well-known/openid-configuration`;
- `/oauth2/jwks.json`;
- GET and POST `/oauth2/userinfo`;
- ID-token issuance when `openid` is granted.

Mounting a router does not make disabled features active. Settings remain the
source of truth for protocol behavior.

Zero Auth Lite currently uses Ed25519/OKP signing keys. It does not implement OIDC
implicit or hybrid response types and has not been externally certified.
