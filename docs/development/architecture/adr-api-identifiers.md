# API Identifiers Use Raw UUIDv4 Values

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
Public resources use raw UUIDv4 values. Field and parameter names provide the
resource context, so identifiers have no `usr_`, `org_`, `ses_`, `oas_`, or
client prefix. Protocol-defined names such as OAuth2 `client_id` and OpenID
Connect `sub` keep their standard meaning. HTTP responses and JWT claims use
the canonical lowercase, hyphenated representation.

Application code uses `uuid.UUID`, HTTP models use Pydantic `UUID4`, and
SQLite stores values through SQLAlchemy `Uuid(as_uuid=True)`. UUIDv4 avoids a
custom codec, node leasing, clock-rollback handling, and shared generator state.
Its costs are larger indexes than 64-bit integers, random insertion order, and
less human-friendly values. Internal relational primary and foreign keys remain
integers, so these costs apply to externally addressable columns and their
indexes rather than every relationship.

This is an intentionally breaking development-schema baseline. Databases and
OAuth2 clients created with the former identifier scheme must be recreated;
there is no mixed reader, alias, or data migration.

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
