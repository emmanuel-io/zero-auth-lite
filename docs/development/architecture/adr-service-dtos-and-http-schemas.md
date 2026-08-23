# Separate HTTP schemas from service DTOs

## Status

Accepted.

## Context

Application services previously accepted FastAPI request schemas and returned
response schemas. That made domain behavior depend on HTTP validation,
serialization aliases, OpenAPI descriptions, and public identifier formatting.
It also made service names ambiguous: a model named `Read` or `Update` could be
either an HTTP contract or an internal transfer object.

OAuth2 client administration had a second ownership problem. One large service
managed registrations, user-backed organization policy, machine organization
policy, and revocation side effects. Bearer-principal resolution also lived in
the OIDC package even though OAuth2-protected application routes use it without
OIDC UserInfo.

These concerns do not apply to standardized OAuth2 and OIDC protocol routes.
Those routes deliberately keep typed FastAPI parameters and protocol-specific
error translation as part of their public contract.

## Decision

Application-owned HTTP request and response models live beside their versioned
routers under `app/api/v1/`. Their names end in `Request` or `Response`.

The cross-cutting application error envelope is the narrow exception. It lives
with `AppError` under `app/core/errors/` because domain exceptions, FastAPI
handlers, and OpenAPI adapters must serialize and document the same payload.
Routes still declare explicitly which application error classes they expose.

Service inputs and outputs live in feature-local `dtos.py` modules. Every
service transfer object ends in `DTO`; supporting protocols, enums, and
principal contexts keep names that describe their role. A versioned route
converts its request schema to a DTO before calling a service and exposes a
response schema rather than returning a service type as its public contract.
Services do not import modules under `app/api/`.

Standardized OAuth2 and OIDC protocol routes remain an explicit exception. Their
transport models may stay with their protocol implementation because request
extraction, OpenAPI, and protocol-error behavior form one standardized boundary.

OAuth2 bearer-principal resolution belongs to `app/oauth2/`, while OIDC retains
only OIDC-specific UserInfo, claims, discovery, JWKS, and ID-token behavior.
Browser users, OAuth2 users, and OAuth2 clients use separate immutable context
types behind small read-only protocols. `PrincipalContext` is the minimal
shared contract, `UserPrincipalContext` carries user-only facts, and
`OAuth2PrincipalContext` is the union of the two bearer context types so
client-only fields cannot appear on a user and browser-only state does not
leak into bearer flows.

OAuth2 client administration is split by capability:

- registration creates a client and returns its one-time credential DTO;
- the registry service reads, updates, and deletes registrations;
- the user-organization service owns user-backed assignments;
- the machine-organization service owns client-credentials organization access;
- the credential service rotates secrets.

Organization-scoped OAuth2 session inspection and revocation live directly
under `app/oauth2/`, outside client registration management.
Their service DTOs carry typed public identifiers. The versioned route parses
incoming serialized identifiers, and its response schema owns prefixes and
field aliases as required by the API-identifier ADR.

OAuth2 client-administration routes catch service errors and translate them at
each endpoint. This repetition is a deliberate, personal project style rather
than a general FastAPI requirement: the local `try`/`except` keeps the transport
boundary and its documented error mapping visible beside every operation. A
global exception handler or decorator would remove repetition, but would also
hide a decision that this reference server prefers to keep explicit.

Client identifier and secret generation is centralized in one module. Policy
narrowing continues to revoke affected sessions inside the service that owns the
mutation. Service-boundary DTOs reject unknown fields, machine access is
replaced only together with its assignments, and bounded assignment sets are
resolved in one query rather than one query per organization.

For SQLite, a single-column index is not retained when an existing composite
index has the same leading column and supports the same lookup. Schema changes
remain represented by reversible Alembic migrations.

## Consequences

HTTP evolution no longer forces service signatures to change, and service tests
can use DTOs without importing API contracts. Route modules contain visible,
deliberate transport conversion. Some fields are represented twice—once as an
internal DTO and once as a public schema—but that duplication documents a real
boundary and prevents transport concerns from leaking inward.

The focused OAuth2 client services have smaller authorization and transaction
surfaces. Moving bearer resolution clarifies that access-token authentication is
OAuth2 infrastructure rather than an OIDC-only feature. Removing redundant
SQLite indexes reduces write amplification while preserving the composite query
paths.
