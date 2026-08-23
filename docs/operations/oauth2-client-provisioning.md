# Provision Machine OAuth2 Clients

A deployment without browser sessions has no authenticated human operator who
can call the `/api/v1/admin/oauth2/clients` routes. Provision confidential
machine clients locally instead of giving a machine token an operator role.

Apply migrations, load the same environment as the server, and run:

```bash
uv run python -m app.oauth2.clients.provision \
  --name "Example worker" \
  --scope organization:read \
  --machine-organization-access none
```

The command prints a JSON object containing `client_id` and `client_secret`.
The raw secret is shown once and is never written to application logs. Store it
in the calling application's secret store.

`--scope` and `--organization-id` are repeatable. Organization access accepts:

- `none`, the safe default, with no organization identifiers;
- `single`, with exactly one public `org_...` identifier;
- `selected`, with one or more public organization identifiers;
- `unrestricted`, with no organization identifiers.

The command checks that assigned organizations exist and serializes concurrent
provisioning through `ZA_RUNTIME_DIR`. It may be run again to create
additional clients. Local database and runtime-directory access are therefore
administrative capabilities and must be restricted to trusted operators.

The resulting client can authenticate at `/oauth2/token` with
`grant_type=client_credentials`. It cannot call human operator routes: OAuth2
scopes restrict a token but never manufacture an operator role.

The canonical `config/client-credentials.example.toml` profile enables only the
Client Credentials grant. It disables Refresh Token because Client Credentials
does not issue refresh tokens. It does not remove the canonical identity
workflow APIs: limiting OAuth2 grants and mounting application-owned identity
routes are separate decisions. A deployment transitioning from interactive
grants may keep Refresh Token enabled only long enough to honor already-issued
families; that transition policy is separate from a fresh Client Credentials
setup.
