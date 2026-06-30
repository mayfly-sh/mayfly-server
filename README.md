# Mayfly Server

Zero-trust SSH certificate authority and control plane.

Mayfly issues short-lived OpenSSH user certificates to engineers who authenticate
with GitHub and are explicitly authorized. Instead of distributing long-lived SSH
keys, hosts trust a single CA public key, and every certificate is minted on demand,
scoped to a principal, and expires within minutes. Each issuance and denial is
recorded in a tamper-evident, append-only audit log.

- **Pluggable identity providers** — GitHub **and** Keycloak/OIDC are first-class
  providers behind one abstraction (`AuthenticationProvider`/`ProviderRegistry`);
  clients select one with an optional `provider` (`?provider=` / body field), and
  adding another provider is "implement the trait + register" (ADR-0018/ADR-0021).
  See `docs/keycloak.md` and `docs/oidc.md`.
- **Device Flow auth** — no passwords or pre-provisioned keys; identity is
  established through the provider's device authorization grant (RFC 8628).
- **Deny-by-default authorization** — provider-neutral allowlists: GitHub user/org/
  team **and** OIDC group/role/attribute. Empty config denies everyone.
- **CA management platform** — manages 1–64 Ed25519 CAs whose metadata lives in SQLite and
  whose encrypted keys live on disk. CAs are generated, imported, enabled, disabled, and
  renamed through an admin API; the CA manager picks an enabled CA per request and signs
  entirely with the `ssh-key` crate (no `ssh-keygen`, no shell-outs).
- **Short-lived certificates** — TTLs are bounded (default 5 minutes, max 1 hour).
- **Tamper-evident audit log** — SHA-256 hash-chained entries persisted to SQLite, with
  fail-closed writes on every security-relevant action.
- **HTTPS only** — a single TLS listener negotiating HTTP/2 or HTTP/1.1 via ALPN, built
  on `rustls` with the `ring` provider. No plaintext transport.
- **Fail-fast startup** — configuration, TLS material, provider credentials (GitHub
  and, when configured, Keycloak), and every stored CA are validated before the
  server accepts connections.
- `#![forbid(unsafe_code)]` crate-wide.

## Requirements

- Rust 1.85+ (edition 2021)
- A GitHub OAuth app configured for the Device Flow (client id + secret)
- A storage passphrase used to encrypt CA keys at rest

## Getting started

### 1. Set the CA storage passphrase

Mayfly is a **CA management server**: it manages **1–64 Ed25519 CAs** whose
metadata lives in the database and whose encrypted private keys live on disk
under `ca.storage_directory`. You do not generate or list CA keys by hand —
the server creates them through the admin API (and bootstraps a first CA,
`mayfly-ca`, on an empty store).

Every CA key is encrypted at rest with a single **storage passphrase**, read at
startup from the environment variable named by `ca.passphrase_env` (default
`CA_STORAGE_PASSPHRASE`) and never written to config:

```bash
export CA_STORAGE_PASSPHRASE='a-strong-storage-passphrase'
```

Startup fails fast (closed) if there are more than 64 CAs, if any key id /
public key / fingerprint is duplicated, if a key is undecryptable or not
Ed25519, or if CAs exist but none is enabled.

Manage CAs at runtime through the admin API (deny-by-default, same authorization
as certificate issuance):

```bash
# Generate a new CA (passphrase must match the storage passphrase).
curl -k -X POST https://127.0.0.1:8443/api/v1/admin/ca/generate \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"key_id":"ca-2026-q3","passphrase":"a-strong-storage-passphrase"}'

# List all CAs, fetch one, or enable/disable/rename it.
curl -k https://127.0.0.1:8443/api/v1/admin/ca -H "authorization: Bearer $TOKEN"
curl -k -X PATCH https://127.0.0.1:8443/api/v1/admin/ca/<id> \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"enabled":false}'
```

### 2. Configure

Copy the example configuration and fill in your provider credentials (GitHub OAuth,
and/or a `keycloak` section for Keycloak/OIDC — see `docs/keycloak.md`):

```bash
cp config.example.yaml config.yaml
```

Configuration is layered, lowest precedence first:

1. Built-in defaults
2. `config.yaml` (override the path with `MAYFLY_CONFIG`)
3. Environment variables prefixed `MAYFLY_`, nesting with `__`

Sensitive values are best supplied via the environment rather than the file:

```bash
export MAYFLY_GITHUB__CLIENT_ID=Iv1.xxxxxxxx
export MAYFLY_GITHUB__CLIENT_SECRET=xxxxxxxx
export MAYFLY_SERVER__PORT=9443
```

> Note: `ca.passphrase_env` must **not** start with `MAYFLY_` — that prefix is reserved
> for configuration variables and would be intercepted by the config loader.

In `development` mode (`environment: development`), a self-signed certificate is
generated automatically under `.mayfly/dev-certs/` so HTTPS works locally without
supplying TLS material. In `production` (the default), explicit `server.tls.cert_path`
and `server.tls.key_path` are required.

### 3. Run

```bash
cargo run
```

The server starts on `https://127.0.0.1:8443` by default. Because development uses a
self-signed certificate, pass `-k` (or the equivalent) to `curl`:

```bash
curl -sk https://127.0.0.1:8443/api/v1/health
```

## API

All endpoints are served under the `/api/v1` prefix.

| Method | Path                        | Auth        | Description                                          |
| ------ | --------------------------- | ----------- | ---------------------------------------------------- |
| `GET`  | `/health`                   | none        | Liveness, version, and uptime.                       |
| `GET`  | `/ready`                    | none        | Readiness checks.                                    |
| `POST` | `/auth/device/start`        | none        | Begin the device flow (optional `?provider=`).       |
| `POST` | `/auth/device/poll`         | none        | Exchange a device code for an access token (body `provider?`). |
| `GET`  | `/auth/whoami`              | Bearer      | Resolve the identity behind a token (optional `?provider=`). |
| `POST` | `/certificates/issue`       | Bearer      | Authenticate, authorize, and sign an SSH certificate.|
| `GET`  | `/certificates/validate`    | none        | Validate a certificate against the CA.               |
| `POST` | `/admin/ca/generate`        | Bearer      | Generate a new encrypted Ed25519 CA.                 |
| `POST` | `/admin/ca/import`          | Bearer      | Import an existing encrypted Ed25519 CA key.         |
| `GET`  | `/admin/ca`                 | Bearer      | List metadata for all managed CAs.                   |
| `GET`  | `/admin/ca/{id}`            | Bearer      | Detailed metadata for one CA (never the private key).|
| `PATCH`| `/admin/ca/{id}`            | Bearer      | Enable, disable, or rename a CA.                     |
| `GET`  | `/admin/ca/{id}/retirement` | Bearer      | Whether a (disabled) CA can be safely retired.       |
| `POST` | `/admin/ca/{id}/retire`     | Bearer      | Permanently retire a disabled CA (`{"force": true}` to override). |
| `GET`  | `/admin/bundle/status`      | Bearer      | Fleet rollout metrics (liveness + machines per generation). |
| `POST` | `/admin/machines/enrollment-tokens` | Bearer | Mint a single-use enrollment token (TTL 60s–24h).        |
| `GET`  | `/admin/machines`           | Bearer      | List enrolled machines (filterable; derived liveness + up-to-date). |
| `GET`  | `/admin/machines/{id}`      | Bearer      | One machine's full detail.                           |
| `POST` | `/admin/machines/{id}/approve` | Bearer   | Approve a pending machine (`pending → active`).      |
| `POST` | `/admin/machines/{id}/disable` | Bearer   | Disable a machine (blocked until re-enabled).        |
| `POST` | `/admin/machines/{id}/enable`  | Bearer   | Re-enable a disabled machine.                        |
| `POST` | `/admin/machines/{id}/revoke`  | Bearer   | Revoke a machine (permanently blocked).              |
| `DELETE`| `/admin/machines/{id}`     | Bearer      | Permanently delete a machine record.                 |
| `POST` | `/admin/machines/{id}/reenroll` | Bearer  | Revoke + mint a fresh single-use enrollment token.   |
| `POST` | `/admin/machines/{id}/rotate-identity` | Bearer | Rotate identity (revoke + new enrollment token). |
| `POST` | `/machines/enroll`          | Token       | Enroll an agent; returns intervals + Bundle Signing Key to pin. |
| `POST` | `/agent/heartbeat`          | Ed25519 sig | Agent liveness heartbeat.                            |
| `GET`  | `/agent/ca-bundle`          | Ed25519 sig | Fetch the current **signed** CA bundle (ETag / `304`).|
| `POST` | `/agent/ca-bundle/ack`      | Ed25519 sig | Report apply outcome (`applied` / `rollback` / `signature_failed`). |

Authenticated endpoints expect an `Authorization: Bearer <provider-access-token>` header
(a GitHub token, or — with `?provider=keycloak` / body `provider` — an OIDC access token).
Agent endpoints are authenticated by a per-request Ed25519 signature, not a bearer token.

### Signed CA bundle distribution

Agents fetch the CA trust bundle from `GET /api/v1/agent/ca-bundle`. The response is a
**versioned, signed artifact** — not just a key list:

```json
{
  "bundle_version": 1,
  "generation": 42,
  "created_at": "2026-06-29T00:00:00Z",
  "expires_at": "2026-06-29T01:00:00Z",
  "fingerprint": "sha256:9f86d081...",
  "keys": [
    { "key_id": "ca-2026-q3", "public_key": "ssh-ed25519 AAAA...", "fingerprint": "SHA256:..." }
  ],
  "signature_algorithm": "ssh-ed25519",
  "signature": "Base64(Ed25519 over the canonical representation)",
  "bundle_signing_public_key": "ssh-ed25519 AAAA... (OpenSSH public key line)"
}
```

The canonical representation that the signature covers is a single-line UTF-8
JSON document with members in fixed (alphabetical) order and keys sorted by
`key_id` (server and agent produce it byte-for-byte identically):

```text
{"bundle_version":1,"created_at":"<rfc3339>","expires_at":"<rfc3339>","fingerprint":"sha256:...","generation":42,"keys":[{"key_id":"ca-2026-q3","public_key":"ssh-ed25519 AAAA..."}]}
```

- **Authenticity:** the signature is computed over a fixed, version-specific *canonical*
  byte layout (never the serialized JSON), using a dedicated **Bundle Signing Key** that is
  distinct from the SSH CA keys. Agents pin this key from the enrollment response and must
  verify the signature (and reject expired bundles) **before** trusting the bundle — failures
  fail closed.
- **Caching:** the response `ETag` is the bundle fingerprint. An up-to-date agent sends
  `If-None-Match: "<fingerprint>"` and receives `304 Not Modified` (no body, no re-signing).
- **Polling:** each agent receives a per-host jittered `sync_interval` (±`jitter_percent`,
  CSPRNG) at enrollment so the fleet does not poll in lockstep.
- **Acknowledgement:** after applying a bundle the agent calls `/agent/ca-bundle/ack` with
  `status: applied` (advances its synced generation), or `rollback` / `signature_failed`
  (audited only). Every outcome is recorded in the audit log.

### Issuing a certificate

The certificate principal is always derived from the authenticated identity (the
provider's username) — never from the request body — so a caller cannot request a
certificate for someone else. This holds for every provider. Add an optional
`"provider"` field to verify the bearer against a non-default provider (e.g.
`"keycloak"`); omit it to use the configured `default_provider`.

```bash
curl -sk -X POST https://127.0.0.1:8443/api/v1/certificates/issue \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "ssh-ed25519 AAAA... user@host",
    "hostname": "bastion.example.com",
    "ttl_seconds": 300,
    "provider": "keycloak"
  }'
```

The response contains the OpenSSH-formatted certificate, its serial, principal,
fingerprint, effective TTL, and validity window.

### Machine administration

The `/admin/machines` endpoints are the control plane for the enrolled fleet and
back the `mayfly machine` CLI (the primary operator interface — no manual REST
calls are required). All of them are **Bearer-authenticated and authorized with
the same deny-by-default policy** as the CA admin API.

- **List / show** project a rich, presentation-neutral view of each machine,
  including derived `liveness` (`online`/`stale`/`offline`) and `up_to_date`
  (synced generation vs. the latest CA generation). `GET /admin/machines`
  filters server-side by `status`, `liveness`, `hostname` (substring),
  `generation`, `os`, `arch`, and `agent_version`.
- **Lifecycle** — `approve`/`enable` set a machine `active`; `disable` and
  `revoke` block it; `delete` removes the record. Because agents are pull-based,
  these take effect at the per-request authentication gate: a machine that is not
  `active` (or no longer exists) has its next signed request rejected, so it stops
  converging immediately — without any change to the agent.
- **Re-enroll / rotate-identity** delete the existing machine (freeing its
  hostname and key) and return a fresh **single-use enrollment token**; applying
  it on the host enrolls a brand-new keypair, which is exactly an identity
  rotation. The old identity is dead the moment the call returns.

Auditing: every **mutation** (`machine.approved`/`disabled`/`enabled`/`revoked`/
`deleted`/`reenroll_requested`/`identity_rotation_requested`) and every
**authorization denial** (`machine.admin_denied`) appends a fail-closed,
hash-chained audit entry recording the **operator identity** and
privacy-preserving **client context**. Read operations (`list`/`get`) are
authorized but intentionally not audited, so CLI `--watch` polling cannot flood
the audit log.

```bash
# List active machines that are offline (operator Bearer token required).
curl -sk "https://127.0.0.1:8443/api/v1/admin/machines?status=active&liveness=offline" \
  -H "Authorization: Bearer $TOKEN"

# Disable, then rotate a machine's identity (returns a single-use token).
curl -sk -X POST https://127.0.0.1:8443/api/v1/admin/machines/<id>/disable \
  -H "Authorization: Bearer $TOKEN"
curl -sk -X POST https://127.0.0.1:8443/api/v1/admin/machines/<id>/rotate-identity \
  -H "Authorization: Bearer $TOKEN"
```

## Configuration reference

| Key                       | Description                                                        |
| ------------------------- | ------------------------------------------------------------------ |
| `environment`             | `development` or `production` (default).                           |
| `server.host` / `port`    | Bind address and port.                                             |
| `server.tls.enabled`      | HTTPS toggle (Mayfly only serves HTTPS).                           |
| `server.tls.cert_path`    | PEM certificate chain (required in production).                    |
| `server.tls.key_path`     | PEM private key (required in production).                          |
| `database.url`            | SQLx connection URL (e.g. `sqlite://mayfly.db`).                   |
| `database.max_connections`| Connection pool size.                                              |
| `logging.format`          | `pretty` (local) or `json` (aggregation).                          |
| `logging.level`           | Tracing filter (e.g. `info`, `mayfly_server=debug`).               |
| `github.client_id`        | GitHub OAuth client id (required).                                 |
| `github.client_secret`    | GitHub OAuth client secret (required; prefer the environment).     |
| `github.scopes`           | OAuth scopes (default `read:user user:email`).                     |
| `github.device_base_url`  | Device/authorization base URL (override for GitHub Enterprise).    |
| `github.api_base_url`     | REST API base URL.                                                 |
| `keycloak.issuer_url`     | OIDC issuer URL (required when `[keycloak]` present). See `docs/keycloak.md`. |
| `keycloak.client_id`      | OIDC client id (required when `[keycloak]` present).              |
| `keycloak.client_secret`  | OIDC client secret (confidential clients only; prefer the environment). |
| `keycloak.scopes`         | OAuth scopes (default `openid profile email`).                     |
| `keycloak.audience`       | Expected token `aud`; enforced only when set (recommended).        |
| `keycloak.clock_skew_seconds` | `exp`/`nbf` leeway in seconds (default `60`).                  |
| `default_provider`        | Provider used when a request omits `provider` (`github` default).  |
| `ca.storage_directory`    | Directory holding the encrypted CA private key files (default `./ca`). |
| `ca.selection_strategy`   | Signing-CA selection strategy (`random`).                          |
| `ca.auto_load`            | Load all stored CAs at startup; bootstrap a first CA if empty (default `true`). |
| `ca.passphrase_env`       | Env var holding the storage passphrase (default `CA_STORAGE_PASSPHRASE`). |
| `bundle.sync_interval_seconds` | Base agent poll cadence in seconds (default `300`).           |
| `bundle.jitter_percent`   | Per-host poll-interval jitter, 0–100 (default `10`).               |
| `bundle.ttl_seconds`      | Signed bundle validity window in seconds (default `3600`).         |
| `bundle.signing_key_env`  | Env var holding the base64 Bundle Signing Key seed (default `BUNDLE_SIGNING_KEY`; generated on disk if unset). |
| `access.allowed_users`    | Usernames always allowed (GitHub login or OIDC `preferred_username`). |
| `access.allowed_orgs`     | GitHub orgs whose members are allowed.                             |
| `access.allowed_teams`    | GitHub teams (`org-login/team-slug`) whose members are allowed.    |
| `access.allowed_groups`   | OIDC groups whose members are allowed (e.g. Keycloak groups).      |
| `access.allowed_roles`    | OIDC roles allowed (`client/role` or bare realm role).             |
| `access.allowed_attributes` | OIDC attributes allowed, each `key=value`.                       |

Access is **deny-by-default**: leaving every `access` list empty denies everyone.
Matching is provider-neutral and case-insensitive — a provider resolves only the
facts the policy references (GitHub queries org/team membership only when those
lists are non-empty, which may require the `read:org` scope). Allowlists are **not**
scoped by provider; for OIDC prefer groups/roles/attributes over `allowed_users`.

## Development

```bash
cargo build          # compile
cargo test           # unit + integration tests
cargo clippy         # lints
cargo fmt            # formatting
```

Integration tests live under `tests/` and cover the server, auth, certificate, and
audit flows.

## License

Apache-2.0.
