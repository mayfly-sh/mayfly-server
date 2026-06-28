-- CA management platform: the authoritative store of every SSH User CA the
-- server manages (1–64). Metadata lives here; the encrypted private key
-- material lives on disk under the configured storage directory, referenced by
-- `key_path`. The private key is never stored in the database.
--
-- `ca_authorities` holds one row per CA. `enabled` rows participate in signing
-- and the public bundle; disabled rows are retained for certificate validation
-- and audit history (there is intentionally no delete).
--
-- `ca_manager_state` is a single-row table holding the monotonic bundle
-- generation, bumped on every lifecycle change (generate, import, enable,
-- disable) but never on certificate issuance.
--
-- Every statement uses IF NOT EXISTS, so applying the migration repeatedly is a
-- no-op and it is safe to run on every startup.

CREATE TABLE IF NOT EXISTS ca_authorities (
    id                   TEXT PRIMARY KEY,
    key_id               TEXT NOT NULL UNIQUE,
    public_key           TEXT NOT NULL UNIQUE,
    fingerprint          TEXT NOT NULL UNIQUE,
    key_path             TEXT NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_at           TEXT NOT NULL,
    enabled_at           TEXT,
    disabled_at          TEXT,
    last_used_at         TEXT,
    issued_certificates  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ca_authorities_enabled ON ca_authorities (enabled);

CREATE TABLE IF NOT EXISTS ca_manager_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    generation  INTEGER NOT NULL
);
