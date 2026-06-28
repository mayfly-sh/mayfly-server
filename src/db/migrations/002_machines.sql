-- Machine enrollment: enrolled agents and the single-use tokens that admit them.
--
-- Two tables:
--   * `machines` — one row per enrolled agent, keyed by the server-issued
--     `machine_id`. `hostname` and `public_key` are unique so the same host or
--     key can never enroll twice (enforced both here and in the service).
--   * `machine_enrollment_tokens` — admission credentials. Only the SHA-256
--     hash of a token is ever stored; the plaintext exists transiently when an
--     admin creates it and is shown exactly once.
CREATE TABLE IF NOT EXISTS machines (
    machine_id    TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL UNIQUE,
    public_key    TEXT NOT NULL UNIQUE,
    os            TEXT NOT NULL,
    arch          TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    status        TEXT NOT NULL,
    last_seen     TEXT,
    enrolled_at   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_machines_status ON machines (status);

CREATE TABLE IF NOT EXISTS machine_enrollment_tokens (
    id         TEXT PRIMARY KEY,
    -- SHA-256 hex digest of the plaintext token. Plaintext is never stored.
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    -- NULL until the token is consumed by a successful enrollment.
    used_at    TEXT,
    created_by TEXT NOT NULL,
    -- 1 = single-use (default), 0 = reusable.
    single_use INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash
    ON machine_enrollment_tokens (token_hash);
