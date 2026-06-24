//! Append-only SQLite persistence for the tamper-evident audit log.
//!
//! The repository exposes only `append_entry`, `latest_entry`, and
//! `list_entries`: there are deliberately **no** update or delete methods, and
//! the schema enforces the same rule with triggers.

use crate::audit::hash::{self, compute_entry_hash, GENESIS_PREVIOUS_HASH};
use crate::audit::model::{AuditEntry, NewAuditEntry};
use crate::errors::AuditError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use sqlx::SqlitePool;

/// Append-only repository over the `audit_log` table.
#[derive(Debug, Clone)]
pub struct AuditRepository {
    pool: SqlitePool,
}

impl AuditRepository {
    /// Create a repository backed by an existing connection pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Append an entry to the hash chain in a single transaction.
    ///
    /// Reading the current tip and inserting the new row happen atomically so
    /// concurrent appends cannot fork the chain. `recorded_at` is truncated to
    /// millisecond precision so the persisted value round-trips through the
    /// canonical form exactly.
    pub async fn append_entry(
        &self,
        new: NewAuditEntry,
        recorded_at: DateTime<Utc>,
    ) -> Result<AuditEntry, AuditError> {
        let recorded_at_text = recorded_at.to_rfc3339_opts(SecondsFormat::Millis, true);
        // Re-parse so the returned entry matches a subsequent read exactly.
        let recorded_at = DateTime::parse_from_rfc3339(&recorded_at_text)
            .map_err(|err| AuditError::Corrupt(format!("invalid recorded_at: {err}")))?
            .with_timezone(&Utc);

        let metadata_text = serde_json::to_string(&new.metadata).map_err(|err| {
            AuditError::Serialization(format!("failed to serialize metadata: {err}"))
        })?;

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

        let canonical_json = hash::canonicalize(
            chain_position,
            &new.event_type,
            &new.actor,
            new.subject.as_deref(),
            &recorded_at,
            &new.metadata,
        )?;
        let entry_hash = compute_entry_hash(&canonical_json, &previous_hash);

        let result = sqlx::query(
            r#"
            INSERT INTO audit_log (
                chain_position,
                event_type,
                actor,
                subject,
                metadata,
                recorded_at,
                previous_hash,
                canonical_json,
                entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(chain_position)
        .bind(&new.event_type)
        .bind(&new.actor)
        .bind(&new.subject)
        .bind(&metadata_text)
        .bind(&recorded_at_text)
        .bind(&previous_hash)
        .bind(&canonical_json)
        .bind(&entry_hash)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(AuditEntry {
            id: result.last_insert_rowid(),
            chain_position,
            event_type: new.event_type,
            actor: new.actor,
            subject: new.subject,
            metadata: new.metadata,
            recorded_at,
            previous_hash,
            canonical_json,
            entry_hash,
        })
    }

    /// Return the most recently appended entry, if any.
    pub async fn latest_entry(&self) -> Result<Option<AuditEntry>, AuditError> {
        let row = sqlx::query_as::<_, AuditRow>(
            "SELECT id, chain_position, event_type, actor, subject, metadata, recorded_at, \
             previous_hash, canonical_json, entry_hash \
             FROM audit_log ORDER BY chain_position DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(AuditEntry::try_from).transpose()
    }

    /// Return every entry ordered by ascending `chain_position`.
    pub async fn list_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT id, chain_position, event_type, actor, subject, metadata, recorded_at, \
             previous_hash, canonical_json, entry_hash \
             FROM audit_log ORDER BY chain_position ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(AuditEntry::try_from).collect()
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AuditRow {
    id: i64,
    chain_position: i64,
    event_type: String,
    actor: String,
    subject: Option<String>,
    metadata: String,
    recorded_at: String,
    previous_hash: String,
    canonical_json: String,
    entry_hash: String,
}

impl TryFrom<AuditRow> for AuditEntry {
    type Error = AuditError;

    fn try_from(row: AuditRow) -> Result<Self, Self::Error> {
        let metadata: Value = serde_json::from_str(&row.metadata)
            .map_err(|err| AuditError::Corrupt(format!("invalid metadata json: {err}")))?;
        let recorded_at = DateTime::parse_from_rfc3339(&row.recorded_at)
            .map_err(|err| AuditError::Corrupt(format!("invalid recorded_at: {err}")))?
            .with_timezone(&Utc);

        Ok(AuditEntry {
            id: row.id,
            chain_position: row.chain_position,
            event_type: row.event_type,
            actor: row.actor,
            subject: row.subject,
            metadata,
            recorded_at,
            previous_hash: row.previous_hash,
            canonical_json: row.canonical_json,
            entry_hash: row.entry_hash,
        })
    }
}

#[cfg(test)]
impl AuditRepository {
    /// Direct pool access for tamper-simulation in tests.
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::model::AuditVerificationResult;
    use crate::audit::verifier::verify_chain;
    use crate::db;
    use chrono::TimeZone;
    use serde_json::json;

    async fn test_repo() -> AuditRepository {
        let pool = db::connect(":memory:").await.expect("connect");
        AuditRepository::new(pool)
    }

    fn event(suffix: &str) -> NewAuditEntry {
        NewAuditEntry::new("test.event", format!("actor-{suffix}"))
            .with_subject(format!("subject-{suffix}"))
            .with_metadata(json!({ "suffix": suffix }))
    }

    fn at(seconds: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, seconds).unwrap()
    }

    /// Drop the append-only triggers to simulate an attacker with raw database
    /// access. In-band tampering through the application is impossible; this
    /// models the out-of-band threat the hash chain exists to detect.
    async fn disable_append_only_guard(repo: &AuditRepository) {
        sqlx::raw_sql("DROP TRIGGER audit_log_no_update; DROP TRIGGER audit_log_no_delete;")
            .execute(repo.pool())
            .await
            .expect("drop triggers");
    }

    #[tokio::test]
    async fn first_append_uses_genesis_and_chain_position_one() {
        let repo = test_repo().await;
        let entry = repo.append_entry(event("01"), at(1)).await.expect("append");

        assert_eq!(entry.chain_position, 1);
        assert_eq!(entry.previous_hash, GENESIS_PREVIOUS_HASH);
        assert_eq!(entry.id, 1);
    }

    #[tokio::test]
    async fn append_links_to_previous_entry_hash() {
        let repo = test_repo().await;
        let first = repo.append_entry(event("01"), at(1)).await.expect("first");
        let second = repo.append_entry(event("02"), at(2)).await.expect("second");

        assert_eq!(second.chain_position, 2);
        assert_eq!(second.previous_hash, first.entry_hash);
    }

    #[tokio::test]
    async fn latest_entry_reports_tip_and_none_when_empty() {
        let repo = test_repo().await;
        assert!(repo.latest_entry().await.expect("empty").is_none());

        repo.append_entry(event("01"), at(1)).await.expect("first");
        let second = repo.append_entry(event("02"), at(2)).await.expect("second");

        let latest = repo.latest_entry().await.expect("latest").expect("some");
        assert_eq!(latest, second);
    }

    #[tokio::test]
    async fn list_entries_round_trips_and_orders_by_chain_position() {
        let repo = test_repo().await;
        let first = repo.append_entry(event("01"), at(1)).await.expect("first");
        let second = repo.append_entry(event("02"), at(2)).await.expect("second");

        let all = repo.list_entries().await.expect("list");
        assert_eq!(all, vec![first, second]);
        assert!(verify_chain(&all).is_valid());
    }

    #[tokio::test]
    async fn triggers_block_in_band_update_and_delete() {
        let repo = test_repo().await;
        repo.append_entry(event("01"), at(1)).await.expect("append");

        let update = sqlx::query("UPDATE audit_log SET actor = 'x' WHERE chain_position = 1")
            .execute(repo.pool())
            .await;
        assert!(update.is_err(), "update must be rejected by trigger");

        let delete = sqlx::query("DELETE FROM audit_log WHERE chain_position = 1")
            .execute(repo.pool())
            .await;
        assert!(delete.is_err(), "delete must be rejected by trigger");
    }

    #[tokio::test]
    async fn detects_out_of_band_tampered_row() {
        let repo = test_repo().await;
        repo.append_entry(event("01"), at(1)).await.expect("first");
        repo.append_entry(event("02"), at(2)).await.expect("second");

        disable_append_only_guard(&repo).await;
        sqlx::query("UPDATE audit_log SET actor = 'intruder' WHERE chain_position = 2")
            .execute(repo.pool())
            .await
            .expect("tamper");

        let entries = repo.list_entries().await.expect("list");
        assert!(matches!(
            verify_chain(&entries),
            AuditVerificationResult::Broken { position: 2, .. }
        ));
    }

    #[tokio::test]
    async fn detects_out_of_band_deleted_row() {
        let repo = test_repo().await;
        repo.append_entry(event("01"), at(1)).await.expect("first");
        repo.append_entry(event("02"), at(2)).await.expect("second");
        repo.append_entry(event("03"), at(3)).await.expect("third");

        disable_append_only_guard(&repo).await;
        sqlx::query("DELETE FROM audit_log WHERE chain_position = 2")
            .execute(repo.pool())
            .await
            .expect("delete");

        let entries = repo.list_entries().await.expect("list");
        assert!(matches!(
            verify_chain(&entries),
            AuditVerificationResult::Broken { position: 3, .. }
        ));
    }
}
