# Documentation Review Checklist

Use this checklist for every authentication, authorization, OAuth2, OIDC, or
canonical-server documentation change.

## Concepts And Flows

- State why the flow exists and what problem it solves.
- Name every actor.
- List the steps in order.
- Identify where authentication happens.
- Identify where authorization happens.
- Name every issued artifact and its purpose.
- State what the client or browser never receives.
- Describe trust assumptions and important failure modes.
- Correct common misconceptions.

## Examples

- Include exact prerequisites and commands.
- List useful URLs and expected results.
- Explain relevant environment variables and defaults.
- Point to the most important source files.
- State what is intentionally omitted.
- Mark development secrets and optional infrastructure clearly.

## TOML Example Profiles

Treat `config/development.example.toml` and
`config/full-server.example.toml` as executable configuration reference
documents, not minimal lists of overrides. Keep
`config/client-credentials.example.toml` as the documented specialized profile.

- Keep both files organized with the same section names and ordering.
- List every supported TOML setting in both profiles.
- Leave code defaults commented with their actual default value.
- Uncomment only values that define the profile topology or must be replaced,
  such as direct-HTTP origins, the Compose SMTP host, and placeholder secrets.
- Explain optional values that cannot have a meaningful literal default, such
  as bootstrap credentials, signing-key rotation entries, and SMTP credentials.
- Mark development-only secrets, insecure HTTP cookies, and deployment
  requirements explicitly.
- Update both profiles and the settings reference whenever a public setting is
  added, renamed, or removed.

## Verification

- Run `uv run --group docs zensical serve` when editing navigation, references, or API docs pages.
- Run `uv run --group docs zensical build --strict`.
- Run `uv run --group docs pytest --no-cov tests/docs/test_snippets.py`.
- Confirm documented imports and relative links.
- Compare documented routes with generated OpenAPI paths.
- For `/oauth2/*` changes, confirm typed FastAPI parameters still generate the
  expected query parameters, form bodies, and security schemes.
- For `/oauth2/*` changes, confirm protocol routes do not advertise `422` and
  normal application APIs still do when appropriate.
- Avoid claiming production guarantees that the code does not implement.
