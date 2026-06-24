CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_position INTEGER UNIQUE NOT NULL,
    serial TEXT NOT NULL,
    username TEXT NOT NULL,
    github_login TEXT NOT NULL,
    hostname TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    hashed_at TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    requester_ip TEXT,
    cert_fingerprint TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_chain_position ON audit_log (chain_position);
