# Keycloak Guide

Mayfly supports Keycloak (and any standards-compliant OIDC provider) as a
**first-class identity provider**, alongside GitHub. Every CLI command —
`login`, `logout`, `whoami`, `ssh`, `cert issue/renew/inspect` — works
identically with Keycloak. This guide covers configuring a realm, the server,
and the CLI.

> Login is **server-brokered** (ADR-0019): the CLI never holds IdP client
> secrets. It sends only the provider id (`keycloak`) to `mayfly-server`, which
> runs the device flow and verifies tokens. All settings below are **server-side**.

## 1. Keycloak realm setup

1. Create (or choose) a realm, e.g. `engineering`. Its issuer is
   `https://kc.example.com/realms/engineering`.
2. Create an **OAuth client** for Mayfly (e.g. `mayfly-cli`):
   - **Standard flow** off; **OAuth 2.0 Device Authorization Grant** on.
   - Public client (no secret) is fine for the device flow; if you make it
     confidential, set the secret server-side (below).
3. (Recommended) Map the facts you authorize on into the **access token**:
   - **Groups** → add a *Group Membership* mapper (add to access token; full
     path optional — Mayfly strips a leading `/`).
   - **Realm/client roles** → Keycloak includes these in `realm_access.roles` /
     `resource_access.<client>.roles` by default.
   - **Attributes** → add *User Attribute* mappers to the access token for any
     `key=value` you want to gate on.
4. (Recommended) Set the token **audience** (`aud`) to a stable value (e.g.
   `mayfly`) via an *Audience* mapper, and configure `keycloak.audience` so the
   server enforces it.

## 2. Server configuration

Add a `[keycloak]` section (YAML below) or use environment variables. `issuer_url`
and `client_id` are required when the section is present; the server validates
this at startup.

```yaml
keycloak:
  issuer_url: "https://kc.example.com/realms/engineering"
  client_id: "mayfly-cli"
  # client_secret: "..."          # confidential clients only (prefer env)
  # scopes: "openid profile email"  # default
  # audience: "mayfly"              # recommended; default does NOT enforce aud
  # clock_skew_seconds: 60          # exp/nbf leeway

# Optionally make Keycloak the default when a request omits ?provider=:
# default_provider: "keycloak"
```

Environment equivalents (preferred for the secret):

```
MAYFLY_KEYCLOAK__ISSUER_URL=https://kc.example.com/realms/engineering
MAYFLY_KEYCLOAK__CLIENT_ID=mayfly-cli
MAYFLY_KEYCLOAK__CLIENT_SECRET=...          # never in the config file
MAYFLY_KEYCLOAK__AUDIENCE=mayfly
MAYFLY_DEFAULT_PROVIDER=keycloak            # optional
```

The server discovers endpoints from `issuer_url`
(`/.well-known/openid-configuration`) and verifies access tokens as JWTs against
the realm JWKS. No `userinfo` round-trip is made.

## 3. Authorization (deny-by-default)

Authorization is provider-neutral and deny-by-default. For Keycloak, prefer
**groups/roles/attributes** over `allowed_users`:

```yaml
access:
  allowed_groups: ["engineering"]          # OIDC groups (leading / stripped)
  allowed_roles:  ["mayfly/operator"]      # client role: "client/role"
  allowed_attributes: ["department=platform"]
```

- Roles are matched as both `client/role` (e.g. `mayfly/operator`) and the bare
  role name. **Prefer `client/role`** in policy — a bare name matches that role
  on *any* client.
- `allowed_users` matches the username (`preferred_username`). It is **not**
  scoped by provider, so a Keycloak username equal to a GitHub login in
  `allowed_users` would be allowed (risk **R-012A-1**). Use groups/roles/
  attributes for Keycloak, or run separate deployments per IdP.

## 4. CLI usage

The provider is selected per profile / flag; the UX is identical to GitHub.

```bash
mayfly login keycloak          # or: mayfly --provider keycloak login
mayfly whoami                  # provider: keycloak, your preferred_username
mayfly ssh web-01              # issues a cert via the keycloak identity
mayfly cert issue --json
```

Set a default so you can omit `--provider`:

```bash
mayfly config set provider keycloak     # or per-profile
```

## 5. Token verification (what the server enforces)

- **Signature** against the realm JWKS; the **algorithm is pinned to the JWK key
  type** (RS*/ES*). `HS*` and `none` are rejected (no algorithm confusion).
- **Issuer** must equal the discovery document issuer.
- **Audience** is enforced only when `keycloak.audience` is set.
- **Expiry/not-before** with `clock_skew_seconds` leeway (default 60s).
- **JWKS rotation**: an unknown `kid` triggers a single rate-limited JWKS refresh
  (≥30s), so key rotation is handled without downtime or refresh storms.

## 6. Audit

Certificate issuance and identity lookups record `provider`, `subject`, `realm`,
`groups`, `roles`, and the privacy-preserving client context — **never** tokens
or secrets. The audit log remains hash-chained and fail-closed.

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `401 the access token is invalid or expired` | wrong realm/issuer, expired token, or `aud` mismatch when `audience` is set |
| `the access token is invalid` on `cert issue` after login | token expired between login and issue — `mayfly login keycloak` again |
| `403 access denied` | identity authenticated but not in any allowlist — add the right group/role/attribute |
| `unknown authentication provider` | `provider=keycloak` sent but no `[keycloak]` section configured server-side |
| startup error `keycloak.issuer_url is required` | `[keycloak]` present but missing issuer/client id |

See also: `docs/oidc.md` (generic OIDC details) and
`.cursor/outputs/analysis/architecture/provider-development.md` (adding a new
provider).
