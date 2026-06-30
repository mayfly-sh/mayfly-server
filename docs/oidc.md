# OIDC Guide (generic providers)

Mayfly's Keycloak provider is a **generic OIDC access-token verifier**. Any
OpenID Connect provider that (a) supports the OAuth 2.0 Device Authorization
Grant (RFC 8628) and (b) issues **JWT access tokens** verifiable against a
published JWKS can be driven through the same `[keycloak]` configuration block.

This document describes the OIDC mechanics so you can reason about other
providers; for Keycloak-specific realm setup see `docs/keycloak.md`.

## Discovery

The server fetches `<issuer_url>/.well-known/openid-configuration` once (cached,
thread-safe) and uses:

- `issuer` — the canonical issuer pinned during JWT validation.
- `jwks_uri` — where signing keys are fetched.
- `device_authorization_endpoint` / `token_endpoint` — the device grant. If
  discovery omits them, the server falls back to Keycloak's conventional paths
  (`/protocol/openid-connect/auth/device` and `/protocol/openid-connect/token`).

## JWKS and key rotation

Signing keys are fetched from `jwks_uri` and cached. When a token presents a
`kid` that is not in the cache, the server performs **one** JWKS refresh,
rate-limited to at most once per 30 seconds, then retries the lookup. This
supports key rotation without restarts and without enabling a refresh-storm DoS.

## Token verification

For every access token the server:

1. Reads the JWT header to get `kid` and `alg`.
2. Looks up the JWK and derives the expected algorithm **from the key type**
   (RSA→RS*, EC→ES*). The header `alg` must equal it; `HS*`/`none` and any
   mismatch are rejected (algorithm-confusion defense).
3. Verifies the signature with the JWK.
4. Validates claims: `iss` == discovery issuer; `aud` == configured `audience`
   (only when set); `exp`/`nbf` within the configured clock-skew leeway.

Identity and authorization are taken from the **verified token** — there is no
`userinfo` round-trip.

## Claim mapping

| Mayfly field | OIDC claim |
|---|---|
| `subject` | `sub` |
| `username` | `preferred_username` (falls back to `sub`) |
| `email` | `email` |
| `display_name` | `name` |
| `realm` | derived from the issuer path (`.../realms/<realm>`), else issuer host |
| `groups` | `groups` (leading `/` stripped) |
| `roles` | `realm_access.roles` + `resource_access.<client>.roles` (as `client/role` **and** bare `role`) |
| `attributes` | other string / string-array top-level claims (bounded: ≤64 keys × ≤64 values) |

## Requirements for a new OIDC provider

To use a provider other than Keycloak through the `[keycloak]` block:

- It must expose a standard discovery document at
  `<issuer>/.well-known/openid-configuration`.
- Access tokens must be **JWTs** signed with an asymmetric key in the JWKS
  (opaque access tokens are not supported by this verifier).
- It must support the device authorization grant for CLI login.

Providers that diverge from these assumptions (e.g. opaque tokens requiring
introspection, non-standard discovery) should be added as their own
`AuthenticationProvider` implementation — see
`.cursor/outputs/analysis/architecture/provider-development.md`.
