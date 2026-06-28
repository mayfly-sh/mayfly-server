-- CA retirement safety columns on `ca_authorities`.
--
-- `disabled_generation` records the bundle generation at which a CA was
-- disabled, i.e. the first generation whose published bundle no longer contains
-- the key. A machine whose synced generation is < `disabled_generation` may
-- still be trusting that key, which is what makes retirement unsafe.
--
-- `retired` marks a CA whose key material has been permanently removed from
-- disk. Retired rows are retained for audit history but are never loaded into
-- the manager and never participate in signing, validation, or the bundle.
--
-- These ALTER TABLEs are not idempotent, so the migration is gated in
-- `db::migrate` on the absence of the `retired` column.

ALTER TABLE ca_authorities ADD COLUMN disabled_generation INTEGER;
ALTER TABLE ca_authorities ADD COLUMN retired INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ca_authorities ADD COLUMN retired_at TEXT;
