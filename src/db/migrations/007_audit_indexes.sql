-- Read-only audit search indexes (013C / ADR-0024).
--
-- The audit log is still append-only and tamper-evident (migration 001); this
-- migration only adds covering indexes so the operational audit search
-- (filter by event type / actor / subject / date range) stays cheap as the log
-- grows. It is fully idempotent (`CREATE INDEX IF NOT EXISTS`) and adds no
-- columns, triggers, or write paths.
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type  ON audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor        ON audit_log (actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_subject      ON audit_log (subject);
CREATE INDEX IF NOT EXISTS idx_audit_log_recorded_at  ON audit_log (recorded_at);
