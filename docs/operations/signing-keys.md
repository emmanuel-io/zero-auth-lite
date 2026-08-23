# Configure Signing Keys

Zero Auth Lite signs JWTs with Ed25519. Configure the private key only on the
authorization server and publish the matching public key through JWKS when
clients need offline verification.

Generate deployment keys outside the repository and provide base64-encoded raw
key material through `OAuth2Settings.prv_key_b64` and
`OAuth2Settings.pub_key_b64`. Also configure a stable issuer, audience, and
non-empty key ID. Tokens verified against the rotation key set must carry this
`kid` header; tokens with a missing, empty, or unknown key ID are rejected
before signature verification.

Never reuse the development keys from the canonical application. Keep private
keys out of source control and logs.

## Rotation

1. Generate a new key pair and key ID.
2. Keep the previous public key in `previous_public_keys`.
3. Start signing new tokens with the new private key.
4. Publish both public keys through JWKS during the overlap.
5. Remove the previous key only after every token signed by it has expired.

Discovery, ID tokens, access tokens, and configured client expectations must
use the same issuer. A hostname, scheme, port, or trailing-slash mismatch is an
issuer mismatch.
