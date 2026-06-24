//! Database connectivity and schema management.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

/// SQL migration that creates the tamper-evident audit log table.
pub const AUDIT_LOG_MIGRATION: &str = include_str!("migrations/001_audit_log.sql");

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
pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(AUDIT_LOG_MIGRATION).execute(pool).await?;
    Ok(())
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
}
