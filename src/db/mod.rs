//! Database connectivity and schema management.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

/// SQL migration that creates the tamper-evident audit log table.
pub const AUDIT_LOG_MIGRATION: &str = include_str!("migrations/001_audit_log.sql");

/// SQL migration that creates the `machines` and `machine_enrollment_tokens`
/// tables backing machine enrollment.
pub const MACHINES_MIGRATION: &str = include_str!("migrations/002_machines.sql");

/// SQL migration adding heartbeat-maintained liveness fields (`ip`,
/// `current_generation`) to `machines`.
pub const MACHINE_PROTOCOL_MIGRATION: &str = include_str!("migrations/003_machine_protocol.sql");

/// SQL migration adding the CA bundle distribution tables (`ca_keys`,
/// `ca_bundle_state`) and per-machine CA-sync acknowledgement columns.
pub const CA_BUNDLE_MIGRATION: &str = include_str!("migrations/004_ca_bundle.sql");

/// SQL migration adding the CA management tables (`ca_authorities`,
/// `ca_manager_state`) that back the multi-key CA manager.
pub const CA_MANAGEMENT_MIGRATION: &str = include_str!("migrations/005_ca_management.sql");

/// SQL migration adding CA retirement-safety columns to `ca_authorities`
/// (`disabled_generation`, `retired`, `retired_at`).
pub const CA_RETIREMENT_MIGRATION: &str = include_str!("migrations/006_ca_retirement.sql");

/// Connect to SQLite and apply audit schema migrations.
///
/// Uses an in-memory database when `database_url` is `:memory:`.
pub async fn connect(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?.create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    migrate(&pool).await?;
    Ok(pool)
}

/// Apply embedded schema migrations.
///
/// Uses [`sqlx::raw_sql`] so every statement in the migration (table, index,
/// and the append-only triggers) is executed — a single prepared `query` would
/// only run the first statement.
///
/// Before applying the schema, any pre-existing `audit_log` table left over
/// from an earlier, incompatible prototype schema is reconciled (see
/// [`reconcile_legacy_audit_log`]). This is what prevents the historical
/// `CREATE TABLE IF NOT EXISTS` from silently skipping a stale table and then
/// failing on a later statement (e.g. `CREATE INDEX ... (chain_position)`)
/// because the stale table lacks the expected columns.
pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    reconcile_legacy_audit_log(pool).await?;

    sqlx::raw_sql(AUDIT_LOG_MIGRATION)
        .execute(pool)
        .await
        .map_err(|err| {
            sqlx::Error::Protocol(format!("failed to apply audit_log schema migration: {err}"))
        })?;

    sqlx::raw_sql(MACHINES_MIGRATION)
        .execute(pool)
        .await
        .map_err(|err| {
            sqlx::Error::Protocol(format!("failed to apply machines schema migration: {err}"))
        })?;

    // `ALTER TABLE ADD COLUMN` is not idempotent, so apply the protocol
    // migration only when its columns are not already present.
    if !column_exists(pool, "machines", "ip").await? {
        sqlx::raw_sql(MACHINE_PROTOCOL_MIGRATION)
            .execute(pool)
            .await
            .map_err(|err| {
                sqlx::Error::Protocol(format!(
                    "failed to apply machine protocol schema migration: {err}"
                ))
            })?;
    }

    // Likewise gate the CA bundle migration on its `machines` columns; the
    // table creates within it all use `IF NOT EXISTS`, so the only
    // non-idempotent statements are the `ALTER TABLE`s.
    if !column_exists(pool, "machines", "synced_generation").await? {
        sqlx::raw_sql(CA_BUNDLE_MIGRATION)
            .execute(pool)
            .await
            .map_err(|err| {
                sqlx::Error::Protocol(format!("failed to apply CA bundle schema migration: {err}"))
            })?;
    }

    // The CA management migration is fully idempotent (every statement uses
    // IF NOT EXISTS), so it can run unconditionally on every startup.
    sqlx::raw_sql(CA_MANAGEMENT_MIGRATION)
        .execute(pool)
        .await
        .map_err(|err| {
            sqlx::Error::Protocol(format!("failed to apply CA management schema migration: {err}"))
        })?;

    // The retirement migration uses non-idempotent `ALTER TABLE ADD COLUMN`, so
    // gate it on the absence of its `retired` column.
    if !column_exists(pool, "ca_authorities", "retired").await? {
        sqlx::raw_sql(CA_RETIREMENT_MIGRATION)
            .execute(pool)
            .await
            .map_err(|err| {
                sqlx::Error::Protocol(format!(
                    "failed to apply CA retirement schema migration: {err}"
                ))
            })?;
    }
    Ok(())
}

/// Whether a column exists on a table.
async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> Result<bool, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?")
            .bind(table)
            .bind(column)
            .fetch_one(pool)
            .await?;
    Ok(count.0 > 0)
}

/// Drop a pre-existing `audit_log` table whose schema predates the current
/// (generic, hash-chained) design, but only when it is empty.
///
/// The current schema is identified by columns the legacy certificate-specific
/// schema never had (`chain_position`, `event_type`, `canonical_json`). If a
/// legacy table is found with rows, we refuse to destroy data and return an
/// actionable error instead of silently dropping it.
async fn reconcile_legacy_audit_log(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    if !table_exists(pool, "audit_log").await? || audit_log_is_current(pool).await? {
        return Ok(());
    }

    let rows = audit_log_row_count(pool).await?;
    if rows > 0 {
        return Err(sqlx::Error::Protocol(format!(
            "audit_log has an incompatible legacy schema and contains {rows} row(s); \
             refusing to drop it automatically — migrate or remove the table manually"
        )));
    }

    tracing::warn!(
        "found an empty, incompatible legacy audit_log table; recreating it with the current schema"
    );
    sqlx::raw_sql("DROP TABLE IF EXISTS audit_log;")
        .execute(pool)
        .await?;
    Ok(())
}

/// Whether a table with the given name exists.
async fn table_exists(pool: &SqlitePool, name: &str) -> Result<bool, sqlx::Error> {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(name)
            .fetch_one(pool)
            .await?;
    Ok(count.0 > 0)
}

/// Whether the existing `audit_log` table matches the current schema.
async fn audit_log_is_current(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pragma_table_info('audit_log') \
         WHERE name IN ('chain_position', 'event_type', 'canonical_json')",
    )
    .fetch_one(pool)
    .await?;
    Ok(count.0 == 3)
}

/// Number of rows in the `audit_log` table.
async fn audit_log_row_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(pool)
        .await?;
    Ok(count.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrate_creates_audit_log_table() {
        let pool = connect(":memory:").await.expect("connect");
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE name = 'audit_log'")
            .fetch_one(&pool)
            .await
            .expect("table exists");
        assert_eq!(row.0, 1);
    }

    #[tokio::test]
    async fn migrate_creates_machine_tables() {
        let pool = connect(":memory:").await.expect("connect");
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name IN ('machines', 'machine_enrollment_tokens')",
        )
        .fetch_one(&pool)
        .await
        .expect("tables exist");
        assert_eq!(row.0, 2);
    }

    #[tokio::test]
    async fn migrate_creates_append_only_triggers() {
        let pool = connect(":memory:").await.expect("connect");
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'audit_log_no_%'",
        )
        .fetch_one(&pool)
        .await
        .expect("triggers exist");
        assert_eq!(row.0, 2);
    }

    /// A single-connection in-memory pool so a manually created table persists
    /// across the subsequent `migrate` call (each `:memory:` connection is an
    /// independent database).
    async fn unmigrated_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::from_str(":memory:")
                    .unwrap()
                    .create_if_missing(true),
            )
            .await
            .expect("pool")
    }

    #[tokio::test]
    async fn migrate_recreates_empty_legacy_table() {
        let pool = unmigrated_pool().await;
        // The pre-refactor prototype schema: certificate-specific, with
        // `chain_position` but none of the current generic columns.
        sqlx::raw_sql(
            "CREATE TABLE audit_log (\
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 chain_position INTEGER UNIQUE NOT NULL, \
                 github_login TEXT NOT NULL, \
                 cert_fingerprint TEXT NOT NULL, \
                 previous_hash TEXT NOT NULL, \
                 entry_hash TEXT NOT NULL);",
        )
        .execute(&pool)
        .await
        .expect("create legacy table");

        migrate(&pool).await.expect("migrate reconciles legacy table");

        // The current generic columns now exist.
        let cols: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM pragma_table_info('audit_log') \
             WHERE name IN ('event_type', 'canonical_json')",
        )
        .fetch_one(&pool)
        .await
        .expect("columns");
        assert_eq!(cols.0, 2);
    }

    #[tokio::test]
    async fn migrate_refuses_to_drop_legacy_table_with_data() {
        let pool = unmigrated_pool().await;
        sqlx::raw_sql(
            "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, chain_position INTEGER, github_login TEXT);\
             INSERT INTO audit_log (chain_position, github_login) VALUES (1, 'octocat');",
        )
        .execute(&pool)
        .await
        .expect("seed legacy data");

        let err = migrate(&pool).await.expect_err("must refuse to drop data");
        assert!(err.to_string().contains("incompatible legacy schema"));
    }

    #[tokio::test]
    async fn migrate_creates_ca_bundle_tables_and_columns() {
        let pool = connect(":memory:").await.expect("connect");
        let tables: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name IN ('ca_keys', 'ca_bundle_state')",
        )
        .fetch_one(&pool)
        .await
        .expect("tables exist");
        assert_eq!(tables.0, 2);

        let cols: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM pragma_table_info('machines') \
             WHERE name IN ('synced_generation', 'bundle_fingerprint', 'last_sync')",
        )
        .fetch_one(&pool)
        .await
        .expect("columns");
        assert_eq!(cols.0, 3);
    }

    #[tokio::test]
    async fn migrate_creates_ca_management_tables() {
        let pool = connect(":memory:").await.expect("connect");
        let tables: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name IN ('ca_authorities', 'ca_manager_state')",
        )
        .fetch_one(&pool)
        .await
        .expect("tables exist");
        assert_eq!(tables.0, 2);
    }

    #[tokio::test]
    async fn migrate_adds_ca_retirement_columns() {
        let pool = connect(":memory:").await.expect("connect");
        let cols: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM pragma_table_info('ca_authorities') \
             WHERE name IN ('disabled_generation', 'retired', 'retired_at')",
        )
        .fetch_one(&pool)
        .await
        .expect("columns");
        assert_eq!(cols.0, 3);
    }

    #[tokio::test]
    async fn migrate_is_idempotent_on_current_schema() {
        let pool = connect(":memory:").await.expect("connect");
        // Running again must be a no-op, not an error.
        migrate(&pool).await.expect("second migrate");
    }
}
