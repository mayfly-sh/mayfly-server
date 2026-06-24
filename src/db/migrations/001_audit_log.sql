-- Tamper-evident, append-only audit log.
--
-- Each row is one security event. `canonical_json` is the deterministic
-- serialization of every business column; `entry_hash = SHA256(canonical_json
-- || previous_hash)` links the rows into a hash chain anchored at a fixed
-- genesis hash. Verification recomputes the canonical form from the columns and
-- compares it to the stored `canonical_json`, so editing any column is detected.
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_position INTEGER UNIQUE NOT NULL,
    event_type     TEXT NOT NULL,
    actor          TEXT NOT NULL,
    subject        TEXT,
    metadata       TEXT NOT NULL,
    recorded_at    TEXT NOT NULL,
    previous_hash  TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    entry_hash     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_chain_position ON audit_log (chain_position);

-- Append-only enforcement at the storage layer (defense in depth). The
-- application exposes no update/delete paths; these triggers stop accidental or
-- malicious in-band mutation. They do not stop an attacker with raw file
-- access, which is precisely what hash-chain verification is designed to catch.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: updates are forbidden');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: deletes are forbidden');
END;
