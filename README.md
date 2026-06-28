# Mayfly Server

Zero-trust SSH certificate authority and control plane.

Mayfly issues short-lived OpenSSH user certificates to engineers who authenticate
with GitHub and are explicitly authorized. Instead of distributing long-lived SSH
keys, hosts trust a single CA public key, and every certificate is minted on demand,
scoped to a principal, and expires within minutes. Each issuance and denial is
recorded in a tamper-evident, append-only audit log.

- **GitHub Device Flow auth** — no passwords or pre-provisioned keys; identity is
  established through GitHub OAuth.
- **Deny-by-default authorization** — access is granted only via explicit user, org,
  or team allowlists.
- **CA management platform** — manages 1–64 Ed25519 CAs whose metadata lives in SQLite and
  whose encrypted keys live on disk. CAs are generated, imported, enabled, disabled, and
  renamed through an admin API; the CA manager picks an enabled CA per request and signs
  entirely with the `ssh-key` crate (no `ssh-keygen`, no shell-outs).
- **Short-lived certificates** — TTLs are bounded (default 5 minutes, max 1 hour).
- **Tamper-evident audit log** — SHA-256 hash-chained entries persisted to SQLite, with
  fail-closed writes on every security-relevant action.
- **HTTPS only** — a single TLS listener negotiating HTTP/2 or HTTP/1.1 via ALPN, built
  on `rustls` with the `ring` provider. No plaintext transport.
- **Fail-fast startup** — configuration, TLS material, GitHub credentials, and every
  stored CA are validated before the server accepts connections.
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

Copy the example configuration and fill in your GitHub OAuth credentials:

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
| `POST` | `/auth/device/start`        | none        | Begin the GitHub Device Flow.                        |
| `POST` | `/auth/device/poll`         | none        | Exchange a device code for an access token.          |
| `GET`  | `/auth/whoami`              | Bearer      | Resolve the GitHub identity behind a token.          |
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
| `POST` | `/machines/enroll`          | Token       | Enroll an agent; returns intervals + Bundle Signing Key to pin. |
| `POST` | `/agent/heartbeat`          | Ed25519 sig | Agent liveness heartbeat.                            |
| `GET`  | `/agent/ca-bundle`          | Ed25519 sig | Fetch the current **signed** CA bundle (ETag / `304`).|
| `POST` | `/agent/ca-bundle/ack`      | Ed25519 sig | Report apply outcome (`applied` / `rollback` / `signature_failed`). |

Authenticated endpoints expect an `Authorization: Bearer <github-access-token>` header.
Agent endpoints are authenticated by a per-request Ed25519 signature, not a bearer token.

### Signed CA bundle distribution

Agents fetch the CA trust bundle from `GET /api/v1/agent/ca-bundle`. The response is a
**versioned, signed artifact** — not just a key list:

```json
{
  "bundle_version": "v1",
  "generation": 42,
  "created_at": "2026-06-29T00:00:00Z",
  "expires_at": "2026-06-29T01:00:00Z",
  "fingerprint": "sha256:9f86d081...",
  "keys": [
    { "key_id": "ca-2026-q3", "public_key": "ssh-ed25519 AAAA...", "fingerprint": "SHA256:..." }
  ],
  "signature_algorithm": "ed25519",
  "signature": "Base64(Ed25519 over the canonical representation)",
  "signing_public_key": "Base64(32-byte Ed25519 public key)"
}
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

The certificate principal is always derived from the authenticated GitHub identity —
never from the request body — so a caller cannot request a certificate for someone else.

```bash
curl -sk -X POST https://127.0.0.1:8443/api/v1/certificates/issue \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "ssh-ed25519 AAAA... user@host",
    "hostname": "bastion.example.com",
    "ttl_seconds": 300
  }'
```

The response contains the OpenSSH-formatted certificate, its serial, principal,
fingerprint, effective TTL, and validity window.

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
| `ca.storage_directory`    | Directory holding the encrypted CA private key files (default `./ca`). |
| `ca.selection_strategy`   | Signing-CA selection strategy (`random`).                          |
| `ca.auto_load`            | Load all stored CAs at startup; bootstrap a first CA if empty (default `true`). |
| `ca.passphrase_env`       | Env var holding the storage passphrase (default `CA_STORAGE_PASSPHRASE`). |
| `bundle.sync_interval_seconds` | Base agent poll cadence in seconds (default `300`).           |
| `bundle.jitter_percent`   | Per-host poll-interval jitter, 0–100 (default `10`).               |
| `bundle.ttl_seconds`      | Signed bundle validity window in seconds (default `3600`).         |
| `bundle.signing_key_env`  | Env var holding the base64 Bundle Signing Key seed (default `BUNDLE_SIGNING_KEY`; generated on disk if unset). |
| `access.allowed_users`    | GitHub logins that are always allowed.                             |
| `access.allowed_orgs`     | GitHub orgs whose members are allowed.                             |
| `access.allowed_teams`    | GitHub teams (`org-login/team-slug`) whose members are allowed.    |

Access is **deny-by-default**: leaving all three `access` lists empty denies everyone.
Org and team membership is only queried from GitHub when the corresponding list is
non-empty (and may require the `read:org` scope). Matching is case-insensitive.

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
