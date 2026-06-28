-- CA bundle distribution: the set of SSH User CA public keys the server
-- distributes to agents, plus a monotonic bundle generation, plus per-machine
-- acknowledgement state.
--
-- `ca_keys` holds one row per CA public key. Only `enabled` rows are
-- distributed. `generation` records the bundle generation at which a key was
-- added (informational); the authoritative, monotonic bundle generation lives
-- in the single-row `ca_bundle_state` table.
--
-- The per-machine columns on `machines` record what each agent last
-- acknowledged: the generation it applied, the bundle fingerprint it confirmed,
-- and when it last synced. They are additive and nullable so this migration is
-- safe to apply to an existing `machines` table.
--
-- The migration is gated in code on the absence of `machines.synced_generation`,
-- and every CREATE uses IF NOT EXISTS, so re-applying it is a no-op.

CREATE TABLE IF NOT EXISTS ca_keys (
    key_id        TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    generation    INTEGER NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ca_bundle_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    generation  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ca_keys_enabled ON ca_keys (enabled);

ALTER TABLE machines ADD COLUMN synced_generation INTEGER;
ALTER TABLE machines ADD COLUMN bundle_fingerprint TEXT;
ALTER TABLE machines ADD COLUMN last_sync TEXT;
