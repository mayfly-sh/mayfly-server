-- Agent protocol: heartbeat-maintained liveness fields on `machines`.
--
-- `ip` is the agent's last self-reported address and `current_generation` its
-- last self-reported configuration generation. Both are updated on each
-- authenticated heartbeat. They are additive and nullable/defaulted so the
-- migration is safe to apply to an existing `machines` table.
--
-- Liveness (ONLINE / STALE / OFFLINE) is NEVER stored: it is always derived
-- from `last_seen` relative to the current time when listing servers.
ALTER TABLE machines ADD COLUMN ip TEXT;
ALTER TABLE machines ADD COLUMN current_generation INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_machines_last_seen ON machines (last_seen);
