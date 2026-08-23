# API Identifiers Hide Persistence Keys

## Context

Database-backed resources have an internal primary key and a stable external
identifier. That distinction protects persistence details and allows internal
keys to change without changing links, tokens, or client data.

Calling the external value `public_id` in an HTTP path or JSON document leaks
that storage distinction into the API. API consumers should not need to know
that another identifier exists.

## Decision

HTTP contracts expose identifiers as `id` or, when the resource must be named,
`<resource>_id`. Route parameters follow the same rule, such as `{user_id}`,
`{organization_id}`, and `{session_id}`. They never use `public_id` as a JSON field,
query parameter, form field, or path-parameter name.

The values accepted and returned by the API are always the stable external
identifiers. Internal database primary keys are never accepted or serialized.
Prefixes such as `usr_`, `org_`, `ses_`, and `oas_` make the external resource
type explicit without revealing the persistence model. Protocol-defined names
such as OAuth2 `client_id` and OpenID Connect `sub` keep their standard meaning.
The current-user authorization view is a projection of an OAuth2 session, so it
reuses that session's `oas_` identifier instead of introducing a second identity
for the same persisted resource.

Snowflake-backed identifiers use a lowercase resource prefix, `_`, and exactly
13 uppercase Crockford Base32 characters. The payload uses
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, is left-padded with `0`, and has one
canonical spelling: lowercase, aliases, signs, separators, and 19-digit decimal
forms are rejected. The first payload character is `0`
through `7` because the stored value must fit in a positive signed `int64`.
Encoding changes only the HTTP, token-claim, and structured-output boundary;
database columns, primary and foreign keys, indexes, and Snowflake generation
remain integers and database lookups use the decoded integer.

Application models, repositories, and services may use `public_id` internally
when they must distinguish the external identifier from a database primary
key. That name stops at the HTTP serialization boundary.

Typed response models use Pydantic aliases and serializers to enforce that
boundary. Routes return those typed models and let FastAPI perform response
validation and serialization. Runtime and OpenAPI tests verify the resulting
HTTP representation; routes do not rebuild response dictionaries manually.

Every non-protocol `application/json` request model rejects unknown properties.
A request may accept arbitrary properties only through an explicitly named and
documented extension field. OAuth2 and OIDC protocol forms keep their specified
parameter-handling and error behavior rather than inheriting this JSON rule.

## Consequences

API consumers work with one identifier vocabulary and cannot accidentally
depend on database keys. Route and response names remain conventional, while
the server keeps the security and migration benefits of separate external
identifiers. The Pydantic serialization boundary must be covered by runtime
and OpenAPI contract tests. Strict JSON request models also prevent
misspelled, obsolete, or persistence-oriented fields from being silently
ignored.
