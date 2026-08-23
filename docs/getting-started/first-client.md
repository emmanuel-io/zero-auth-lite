# Your First OAuth2 Client

This walkthrough uses the built-in authentication UI and the local Compose
HTTPS topology. It follows Authorization Code with PKCE because that flow makes
the browser, user, client, and authorization server responsibilities visible.

Start the Compose stack as described in [Installation](installation.md), finish
the initial operator bootstrap, and keep these values for the commands below:

```bash
export ZA_URL="https://auth.zero-auth-lite.localhost:8443"
export REDIRECT_URI="http://127.0.0.1:8001/callback"
```

## Register A Public Client

Open the browser developer tools, select the Network panel, and then open
`https://auth.zero-auth-lite.localhost:8443/login`. Sign in as the bootstrapped
operator. Password authentication happens here, before OAuth2 issues any
authorization code. You can inspect the management contract at
`https://auth.zero-auth-lite.localhost:8443/api/docs`.

In the Network panel, select the `POST /login` response and copy its
`X-CSRF-Token` response header. The built-in login response exposes the token
bound to the new session; the JSON-only `/api/v1/sessions/csrf` initializer is
not mounted in this mode.

In the developer console of that same browser tab, paste the copied value into
`csrfToken`, then run this request. The browser sends its `HttpOnly` session
cookie automatically:

```javascript
const csrfToken = "paste-the-X-CSRF-Token-response-header-here";
const clientResponse = await fetch("/api/v1/admin/oauth2/clients", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
  },
  body: JSON.stringify({
    name: "First local client",
    grant_types: ["authorization_code", "refresh_token"],
    scopes: ["openid"],
    redirect_uris: ["http://127.0.0.1:8001/callback"],
    is_confidential: false,
    requires_consent: true,
    is_active: true,
    user_organization_access: "unrestricted",
  }),
});
console.log(await clientResponse.json());
```

Copy the returned `client_id`. This is a public client, so it has no client
secret:

```bash
export CLIENT_ID="oa_replace_with_the_returned_client_id"
```

## Create The Browser Authorization Request

Generate a PKCE verifier and its S256 challenge, plus `state` and OIDC `nonce`
values. Keep this terminal open: the verifier is needed after the callback.

```bash
eval "$(uv run python - <<'PY'
import base64
import hashlib
import secrets
import shlex

verifier = secrets.token_urlsafe(64)
challenge = base64.urlsafe_b64encode(
    hashlib.sha256(verifier.encode()).digest()
).rstrip(b"=").decode()
values = {
    "CODE_VERIFIER": verifier,
    "CODE_CHALLENGE": challenge,
    "OAUTH2_STATE": secrets.token_urlsafe(32),
    "OIDC_NONCE": secrets.token_urlsafe(32),
}
for name, value in values.items():
    print(f"export {name}={shlex.quote(value)}")
PY
)"
```

Build the exact authorization URL:

```bash
export AUTHORIZATION_URL="$(uv run python - <<'PY'
import os
from urllib.parse import urlencode

query = urlencode({
    "response_type": "code",
    "client_id": os.environ["CLIENT_ID"],
    "redirect_uri": os.environ["REDIRECT_URI"],
    "scope": "openid",
    "code_challenge": os.environ["CODE_CHALLENGE"],
    "code_challenge_method": "S256",
    "state": os.environ["OAUTH2_STATE"],
    "nonce": os.environ["OIDC_NONCE"],
})
print(f'{os.environ["ZA_URL"]}/oauth2/authorize?{query}')
PY
)"
printf '%s\n' "$AUTHORIZATION_URL"
```

## Receive The Callback

Start this one-request loopback listener in the same terminal. It rejects a
callback whose `state` does not match and stores the short-lived authorization
code in a temporary file.

```bash
export CALLBACK_CODE_FILE="$(mktemp)"
uv run python - "$OAUTH2_STATE" "$CALLBACK_CODE_FILE" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import html
import sys
from urllib.parse import parse_qs, urlsplit

expected_state = sys.argv[1]
code_file = Path(sys.argv[2])


class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        values = parse_qs(urlsplit(self.path).query)
        state = values.get("state", [None])[0]
        code = values.get("code", [None])[0]
        if state != expected_state or code is None:
            self.send_response(400)
            message = "Invalid OAuth2 callback state or missing code."
        else:
            code_file.write_text(code)
            self.send_response(200)
            message = "Authorization code received. Return to the terminal."
        body = f"<h1>{html.escape(message)}</h1>".encode()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


HTTPServer(("127.0.0.1", 8001), CallbackHandler).handle_request()
PY
```

While the listener is waiting, open the printed `AUTHORIZATION_URL` in the
browser where the operator is signed in. Zero Auth Lite validates the client,
redirect URI, scopes, and PKCE challenge, then asks the user to approve the
requested access. The authorization code does not authenticate the user; it is
a temporary artifact created only after browser authentication and consent.

After approval, the listener exits. Load the code and remove its temporary
file:

```bash
export AUTHORIZATION_CODE="$(cat "$CALLBACK_CODE_FILE")"
rm "$CALLBACK_CODE_FILE"
```

## Exchange The Code

The public client sends the original verifier directly to the token endpoint.
Neither the code nor the verifier belongs in a query string.

```bash
export TOKEN_RESPONSE="$(curl --fail-with-body --silent --show-error \
  --insecure \
  --request POST "$ZA_URL/oauth2/token" \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code=$AUTHORIZATION_CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "code_verifier=$CODE_VERIFIER")"
printf '%s' "$TOKEN_RESPONSE" | uv run python -m json.tool
```

Extract the bearer access token and call UserInfo:

```bash
export ACCESS_TOKEN="$(printf '%s' "$TOKEN_RESPONSE" | uv run python -c \
  'import json, sys; print(json.load(sys.stdin)["access_token"])')"
curl --fail-with-body --silent --show-error \
  --insecure \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  "$ZA_URL/oauth2/userinfo" | uv run python -m json.tool
curl --fail-with-body --silent --show-error \
  --insecure \
  "$ZA_URL/oauth2/jwks.json" | uv run python -m json.tool
```

`--insecure` is limited to this local Caddy development certificate. Do not
disable TLS certificate verification against a deployed issuer.

The token response also contains an ID token and a refresh token. A real client
must keep the PKCE verifier private until exchange, compare the callback
`state`, validate the ID token signature against the issuer's JWKS, and verify
its `iss`, `aud`, expiry, and `nonce` claims. UserInfo uses the access token; the
ID token tells the client how and when the user was authenticated. See
[OpenID Connect](../guides/openid-connect.md) and
[OAuth2 flows](../guides/oauth2-flows.md) for those validation rules.

An external frontend follows the separate
[external authentication UI](../guides/external-authentication-ui.md) contract
and is intentionally not mixed into this first run.
