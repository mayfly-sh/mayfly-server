//! SQLite persistence for the tamper-evident audit log.

use crate::audit::hash::{compute_entry_hash, GENESIS_PREVIOUS_HASH};
use crate::audit::model::{AuditLogEntry, NewAuditLogEntry};
use crate::audit::verifier::verify_chain;
use crate::errors::AuditError;
use sqlx::SqlitePool;

/// Repository for append-only audit log persistence and verification.
#[derive(Debug, Clone)]
pub struct AuditRepository {
    pool: SqlitePool,
}

impl AuditRepository {
    /// Create a repository backed by an existing connection pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Append a new entry to the hash chain inside a transaction.
    pub async fn append_entry(&self, entry: NewAuditLogEntry) -> Result<AuditLogEntry, AuditError> {
        let mut tx = self.pool.begin().await?;

        let latest: Option<(i64, String)> = sqlx::query_as(
            "SELECT chain_position, entry_hash FROM audit_log ORDER BY chain_position DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;

        let (chain_position, previous_hash) = match latest {
            Some((position, hash)) => (position + 1, hash),
            None => (1, GENESIS_PREVIOUS_HASH.to_string()),
        };

        let entry_hash = compute_entry_hash(&entry.hash_input(), &previous_hash)?;

        let result = sqlx::query(
            r#"
            INSERT INTO audit_log (
                chain_position,
                serial,
                username,
                github_login,
                hostname,
                issued_at,
                hashed_at,
                ttl_seconds,
                requester_ip,
                cert_fingerprint,
                previous_hash,
                entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(chain_position)
        .bind(&entry.serial)
        .bind(&entry.username)
        .bind(&entry.github_login)
        .bind(&entry.hostname)
        .bind(&entry.issued_at)
        .bind(&entry.hashed_at)
        .bind(entry.ttl_seconds)
        .bind(&entry.requester_ip)
        .bind(&entry.cert_fingerprint)
        .bind(&previous_hash)
        .bind(&entry_hash)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(AuditLogEntry {
            id: result.last_insert_rowid(),
            chain_position,
            serial: entry.serial,
            username: entry.username,
            github_login: entry.github_login,
            hostname: entry.hostname,
            issued_at: entry.issued_at,
            hashed_at: entry.hashed_at,
            ttl_seconds: entry.ttl_seconds,
            requester_ip: entry.requester_ip,
            cert_fingerprint: entry.cert_fingerprint,
            previous_hash,
            entry_hash,
        })
    }

    /// Fetch a single entry by `chain_position`.
    pub async fn fetch_entry(&self, chain_position: i64) -> Result<AuditLogEntry, AuditError> {
        let row = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT
                id,
                chain_position,
                serial,
                username,
                github_login,
                hostname,
                issued_at,
                hashed_at,
                ttl_seconds,
                requester_ip,
                cert_fingerprint,
                previous_hash,
                entry_hash
            FROM audit_log
            WHERE chain_position = ?
            "#,
        )
        .bind(chain_position)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AuditError::NotFound(chain_position))?;

        Ok(row.into())
    }

    /// Fetch all entries ordered by ascending `chain_position`.
    pub async fn fetch_all(&self) -> Result<Vec<AuditLogEntry>, AuditError> {
        let rows = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT
                id,
                chain_position,
                serial,
                username,
                github_login,
                hostname,
                issued_at,
                hashed_at,
                ttl_seconds,
                requester_ip,
                cert_fingerprint,
                previous_hash,
                entry_hash
            FROM audit_log
            ORDER BY chain_position ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(AuditLogEntry::from).collect())
    }

    /// Load the chain from the database and verify integrity.
    pub async fn verify_chain(&self) -> Result<(), AuditError> {
        let entries = self.fetch_all().await?;
        verify_chain(&entries)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AuditLogRow {
    id: i64,
    chain_position: i64,
    serial: String,
    username: String,
    github_login: String,
    hostname: String,
    issued_at: String,
    hashed_at: String,
    ttl_seconds: i64,
    requester_ip: Option<String>,
    cert_fingerprint: String,
    previous_hash: String,
    entry_hash: String,
}

impl From<AuditLogRow> for AuditLogEntry {
    fn from(row: AuditLogRow) -> Self {
        Self {
            id: row.id,
            chain_position: row.chain_position,
            serial: row.serial,
            username: row.username,
            github_login: row.github_login,
            hostname: row.hostname,
            issued_at: row.issued_at,
            hashed_at: row.hashed_at,
            ttl_seconds: row.ttl_seconds,
            requester_ip: row.requester_ip,
            cert_fingerprint: row.cert_fingerprint,
            previous_hash: row.previous_hash,
            entry_hash: row.entry_hash,
        }
    }
}

#[cfg(test)]
impl AuditRepository {
    /// Direct pool access for tamper-simulation in tests.
    fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn sample_entry(suffix: &str) -> NewAuditLogEntry {
        NewAuditLogEntry {
            serial: format!("serial-{suffix}"),
            username: format!("user-{suffix}"),
            github_login: format!("gh-{suffix}"),
            hostname: format!("host-{suffix}"),
            issued_at: format!("2026-06-24T12:00:{suffix}Z"),
            hashed_at: format!("2026-06-24T12:00:{suffix}Z"),
            ttl_seconds: 3600,
            requester_ip: Some("203.0.113.1".into()),
            cert_fingerprint: format!("fp-{suffix}"),
        }
    }

    async fn test_repo() -> AuditRepository {
        let pool = db::connect(":memory:").await.expect("connect");
        AuditRepository::new(pool)
    }

    #[tokio::test]
    async fn insert_and_fetch_entry() {
        let repo = test_repo().await;
        let inserted = repo.append_entry(sample_entry("01")).await.expect("insert");

        assert_eq!(inserted.chain_position, 1);
        assert_eq!(inserted.previous_hash, GENESIS_PREVIOUS_HASH);

        let fetched = repo.fetch_entry(1).await.expect("fetch");
        assert_eq!(fetched, inserted);
    }

    #[tokio::test]
    async fn append_links_previous_hash() {
        let repo = test_repo().await;
        let first = repo.append_entry(sample_entry("01")).await.expect("first");
        let second = repo.append_entry(sample_entry("02")).await.expect("second");

        assert_eq!(second.chain_position, 2);
        assert_eq!(second.previous_hash, first.entry_hash);
    }

    #[tokio::test]
    async fn verify_chain_through_database() {
        let repo = test_repo().await;
        repo.append_entry(sample_entry("01")).await.expect("first");
        repo.append_entry(sample_entry("02")).await.expect("second");
        repo.append_entry(sample_entry("03")).await.expect("third");

        repo.verify_chain().await.expect("valid chain");
    }

    #[tokio::test]
    async fn detect_tampered_entry_in_database() {
        let repo = test_repo().await;
        repo.append_entry(sample_entry("01")).await.expect("first");
        repo.append_entry(sample_entry("02")).await.expect("second");

        sqlx::query("UPDATE audit_log SET username = 'tampered' WHERE chain_position = 2")
            .execute(repo.pool())
            .await
            .expect("tamper");

        let err = repo.verify_chain().await.expect_err("tampered chain");
        assert!(matches!(
            err,
            AuditError::ChainBroken { position: 2, .. }
        ));
    }

    #[tokio::test]
    async fn fetch_missing_entry_returns_not_found() {
        let repo = test_repo().await;
        let err = repo.fetch_entry(1).await.expect_err("missing");
        assert!(matches!(err, AuditError::NotFound(1)));
    }

    #[tokio::test]
    async fn detect_deleted_entry_in_database() {
        let repo = test_repo().await;
        repo.append_entry(sample_entry("01")).await.expect("first");
        repo.append_entry(sample_entry("02")).await.expect("second");
        repo.append_entry(sample_entry("03")).await.expect("third");

        sqlx::query("DELETE FROM audit_log WHERE chain_position = 2")
            .execute(repo.pool())
            .await
            .expect("delete middle entry");

        let err = repo.verify_chain().await.expect_err("broken chain");
        assert!(matches!(
            err,
            AuditError::ChainBroken { position: 3, .. }
        ));
    }
}
