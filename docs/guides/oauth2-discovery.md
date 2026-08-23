# OAuth2 And OIDC Discovery

Metadata URLs and every endpoint URL in metadata are derived from the
configured absolute HTTP(S) issuer, not from an incoming Host header.

For issuer `https://auth.example`, canonical metadata lives at:

```text
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```

For issuer `https://auth.example/oauth2`, the two standards construct their
paths differently:

```text
/.well-known/oauth-authorization-server/oauth2
/oauth2/.well-known/openid-configuration
```

Metadata advertises only enabled grants and implemented client authentication
methods. PKCE advertises only `S256`; password, implicit, and hybrid flows are
not advertised. OIDC discovery requires `jwks_uri`. Discovery, access tokens,
ID tokens, and introspection use the exact same issuer.

The token endpoint advertises `none` only while an enabled grant accepts public
clients. Zero Auth Lite does not implement JWT-based client authentication, so it
does not publish client-authentication signing algorithms. OAuth scopes are
registered per client and therefore are not exposed as a misleading exhaustive
`scopes_supported` list in OAuth2 metadata. The separate OIDC discovery
document publishes the fixed scopes implemented by the OIDC layer.
Both OAuth2 and OIDC metadata publish the same implemented token endpoint
authentication methods.

When every grant is disabled but JWKS remains enabled, OAuth2 metadata and the
JWKS endpoint remain available while token, revocation, and introspection URLs
are omitted. Their HTTP routes are not mounted in that configuration.

Zero Auth Lite publishes Ed25519/OKP verification keys. Every key has a unique
`kid`, JWT headers reference a published key, private key material is never
published, and retained verification keys remain available during rotation.

This is an implemented, internally tested protocol subset. No external OAuth2
or OpenID Connect conformance suite has been recorded, and the project does
not claim certification.
