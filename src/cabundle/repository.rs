//! Persistence for the CA bundle: the key set, the monotonic generation, the
//! one-time seed of the server's own CA key, and per-machine acknowledgement
//! state.
//!
//! The trait comes first so [`crate::cabundle::service::CaBundleService`] depends
//! on an abstraction; the SQLite implementation follows.

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{Connection, SqliteConnection};

use crate::cabundle::models::CaKeyRecord;

/// Render a timestamp the way it is stored (RFC 3339, millisecond precision).
fn to_text(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Read access to the CA key set plus the bundle acknowledgement write path.
#[async_trait]
pub trait CaKeyRepository: Send + Sync {
    /// The current monotonic bundle generation, or `0` if none is recorded.
    async fn current_generation(&self, conn: &mut SqliteConnection) -> Result<i64, sqlx::Error>;

    /// All enabled CA keys, ordered by `key_id`.
    async fn list_enabled(
        &self,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<CaKeyRecord>, sqlx::Error>;

    /// Record a machine's acknowledgement of a synced generation/fingerprint.
    ///
    /// Returns `true` if a machine row was updated, `false` if none matched.
    async fn record_ack(
        &self,
        conn: &mut SqliteConnection,
        machine_id: &str,
        generation: i64,
        fingerprint: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error>;

    /// Seed the bundle with a single CA key at generation 1, **only** if the
    /// key set is currently empty. Idempotent across restarts.
    async fn ensure_seeded(
        &self,
        conn: &mut SqliteConnection,
        key_id: &str,
        public_key: &str,
        now: DateTime<Utc>,
    ) -> Result<(), sqlx::Error>;
}

/// SQLite-backed [`CaKeyRepository`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteCaKeyRepository;

#[derive(sqlx::FromRow)]
struct CaKeyRow {
    key_id: String,
    public_key: String,
    created_at: String,
    generation: i64,
    enabled: i64,
}

impl From<CaKeyRow> for CaKeyRecord {
    fn from(row: CaKeyRow) -> Self {
        Self {
            key_id: row.key_id,
            public_key: row.public_key,
            created_at: row.created_at,
            generation: row.generation,
            enabled: row.enabled != 0,
        }
    }
}

#[async_trait]
impl CaKeyRepository for SqliteCaKeyRepository {
    async fn current_generation(&self, conn: &mut SqliteConnection) -> Result<i64, sqlx::Error> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT generation FROM ca_bundle_state WHERE id = 1")
                .fetch_optional(&mut *conn)
                .await?;
        Ok(row.map(|r| r.0).unwrap_or(0))
    }

    async fn list_enabled(
        &self,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<CaKeyRecord>, sqlx::Error> {
        let rows = sqlx::query_as::<_, CaKeyRow>(
            "SELECT key_id, public_key, created_at, generation, enabled \
             FROM ca_keys WHERE enabled = 1 ORDER BY key_id",
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().map(CaKeyRecord::from).collect())
    }

    async fn record_ack(
        &self,
        conn: &mut SqliteConnection,
        machine_id: &str,
        generation: i64,
        fingerprint: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let now_text = to_text(now);
        let result = sqlx::query(
            "UPDATE machines \
             SET synced_generation = ?, bundle_fingerprint = ?, last_sync = ?, updated_at = ? \
             WHERE machine_id = ?",
        )
        .bind(generation)
        .bind(fingerprint)
        .bind(&now_text)
        .bind(&now_text)
        .bind(machine_id)
        .execute(&mut *conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn ensure_seeded(
        &self,
        conn: &mut SqliteConnection,
        key_id: &str,
        public_key: &str,
        now: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = conn.begin().await?;

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ca_keys")
            .fetch_one(&mut *tx)
            .await?;
        if count.0 == 0 {
            sqlx::query(
                "INSERT INTO ca_keys (key_id, public_key, created_at, generation, enabled) \
                 VALUES (?, ?, ?, 1, 1)",
            )
            .bind(key_id)
            .bind(public_key)
            .bind(to_text(now))
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO ca_bundle_state (id, generation) VALUES (1, 1) \
                 ON CONFLICT(id) DO UPDATE SET generation = 1",
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use chrono::TimeZone;

    fn at(seconds: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, seconds).unwrap()
    }

    async fn conn() -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
        let pool = db::connect(":memory:").await.expect("connect");
        pool.acquire().await.expect("acquire")
    }

    const KEY_A: &str = "ssh-ed25519 AAAAaaaa";
    const KEY_B: &str = "ssh-ed25519 BBBBbbbb";

    #[tokio::test]
    async fn empty_store_reports_zero_generation_and_no_keys() {
        let mut c = conn().await;
        let repo = SqliteCaKeyRepository;
        assert_eq!(repo.current_generation(&mut c).await.unwrap(), 0);
        assert!(repo.list_enabled(&mut c).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ensure_seeded_inserts_once() {
        let mut c = conn().await;
        let repo = SqliteCaKeyRepository;
        repo.ensure_seeded(&mut c, "mayfly-ca", KEY_A, at(0))
            .await
            .unwrap();
        assert_eq!(repo.current_generation(&mut c).await.unwrap(), 1);
        let keys = repo.list_enabled(&mut c).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "mayfly-ca");
        assert_eq!(keys[0].public_key, KEY_A);

        // Seeding again with a different key is a no-op: the store is not empty.
        repo.ensure_seeded(&mut c, "other", KEY_B, at(1))
            .await
            .unwrap();
        let keys = repo.list_enabled(&mut c).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "mayfly-ca");
    }

    #[tokio::test]
    async fn list_enabled_filters_disabled_and_orders_by_key_id() {
        let mut c = conn().await;
        let repo = SqliteCaKeyRepository;
        repo.ensure_seeded(&mut c, "ca-02", KEY_B, at(0))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO ca_keys (key_id, public_key, created_at, generation, enabled) \
             VALUES ('ca-01', ?, ?, 2, 1), ('ca-03', 'ssh-ed25519 CCCC', ?, 3, 0)",
        )
        .bind(KEY_A)
        .bind(to_text(at(1)))
        .bind(to_text(at(2)))
        .execute(&mut *c)
        .await
        .unwrap();

        let keys = repo.list_enabled(&mut c).await.unwrap();
        let ids: Vec<&str> = keys.iter().map(|k| k.key_id.as_str()).collect();
        // ca-03 is disabled and excluded; remaining are sorted.
        assert_eq!(ids, vec!["ca-01", "ca-02"]);
    }

    #[tokio::test]
    async fn record_ack_updates_existing_machine() {
        use crate::machines::models::{MachineStatus, NewMachine};
        use crate::machines::repository::{MachineRepository, SqliteMachineRepository};

        let mut c = conn().await;
        SqliteMachineRepository
            .insert(
                &mut c,
                &NewMachine {
                    machine_id: "srv_1".to_string(),
                    hostname: "h1".to_string(),
                    public_key: "ssh-ed25519 KKKK".to_string(),
                    os: "linux".to_string(),
                    arch: "x86_64".to_string(),
                    agent_version: "0.1.0".to_string(),
                    status: MachineStatus::Active,
                    enrolled_at: at(0),
                },
            )
            .await
            .unwrap();

        let repo = SqliteCaKeyRepository;
        assert!(repo
            .record_ack(&mut c, "srv_1", 5, "sha256:abc", at(10))
            .await
            .unwrap());
        assert!(!repo
            .record_ack(&mut c, "missing", 5, "sha256:abc", at(10))
            .await
            .unwrap());

        let row: (Option<i64>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT synced_generation, bundle_fingerprint, last_sync FROM machines WHERE machine_id = 'srv_1'",
        )
        .fetch_one(&mut *c)
        .await
        .unwrap();
        assert_eq!(row.0, Some(5));
        assert_eq!(row.1.as_deref(), Some("sha256:abc"));
        assert!(row.2.is_some());
    }
}
