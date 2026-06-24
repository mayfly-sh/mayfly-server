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
- **In-memory Ed25519 CA** — the encrypted CA key is decrypted into memory at startup
  and used to sign certificates entirely with the `ssh-key` crate (no `ssh-keygen`,
  no shell-outs).
- **Short-lived certificates** — TTLs are bounded (default 5 minutes, max 1 hour).
- **Tamper-evident audit log** — SHA-256 hash-chained entries persisted to SQLite, with
  fail-closed writes on every security-relevant action.
- **HTTPS only** — a single TLS listener negotiating HTTP/2 or HTTP/1.1 via ALPN, built
  on `rustls` with the `ring` provider. No plaintext transport.
- **Fail-fast startup** — configuration, TLS material, GitHub credentials, and the CA
  key are all validated before the server accepts connections.
- `#![forbid(unsafe_code)]` crate-wide.

## Requirements

- Rust 1.85+ (edition 2021)
- A GitHub OAuth app configured for the Device Flow (client id + secret)
- An encrypted OpenSSH Ed25519 CA private key

## Getting started

### 1. Generate a CA key

The CA key **must** be an encrypted OpenSSH Ed25519 private key. Set a passphrase
when prompted.

```bash
ssh-keygen -t ed25519 -f ./ca/ca_key -C mayfly-ca
export CA_PASSPHRASE='your-passphrase'
```

The passphrase is read at startup from the environment variable named by
`ca.passphrase_env` (default `CA_PASSPHRASE`) and is never written to config.

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

Authenticated endpoints expect an `Authorization: Bearer <github-access-token>` header.

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
| `ca.private_key_path`     | Path to the encrypted Ed25519 CA key.                              |
| `ca.passphrase_env`       | Name of the env var holding the CA passphrase.                     |
| `ca.key_id`               | `key_id` embedded in issued certificates.                          |
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
