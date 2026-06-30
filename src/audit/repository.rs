//! Append-only SQLite persistence for the tamper-evident audit log.
//!
//! The repository exposes only `append_entry`, `latest_entry`, and
//! `list_entries`: there are deliberately **no** update or delete methods, and
//! the schema enforces the same rule with triggers.

use crate::audit::hash::{self, compute_entry_hash, GENESIS_PREVIOUS_HASH};
use crate::audit::model::{AuditEntry, NewAuditEntry};
use crate::audit::query::{AuditPage, AuditQuery, Order, ResultFilter};
use crate::errors::AuditError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

/// SQL predicate (no user input) that marks an event type as a failure. Used by
/// the `result` filter; mirrors [`crate::audit::query::FAILURE_KEYWORDS`].
const FAILURE_PREDICATE: &str = "(lower(event_type) LIKE '%denied%' \
     OR lower(event_type) LIKE '%failed%' \
     OR lower(event_type) LIKE '%rejected%' \
     OR lower(event_type) LIKE '%rollback%' \
     OR lower(event_type) LIKE '%error%')";

/// Escape SQLite `LIKE` metacharacters so a prefix is matched literally. The
/// query uses `ESCAPE '\'`.
fn like_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Push the shared `WHERE` clause for [`AuditQuery`] onto a builder. Kept
/// separate so `search` and `count` filter identically.
fn push_filters(qb: &mut QueryBuilder<'_, Sqlite>, query: &AuditQuery) {
    let mut first = true;
    let mut sep = |qb: &mut QueryBuilder<'_, Sqlite>| {
        if first {
            qb.push(" WHERE ");
            first = false;
        } else {
            qb.push(" AND ");
        }
    };

    if let Some(event_type) = query.event_type.as_deref() {
        sep(qb);
        qb.push("event_type = ").push_bind(event_type.to_string());
    }
    if let Some(prefix) = query.event_prefix.as_deref() {
        sep(qb);
        qb.push("event_type LIKE ")
            .push_bind(format!("{}%", like_escape(prefix)))
            .push(" ESCAPE '\\'");
    }
    if let Some(actor) = query.actor.as_deref() {
        sep(qb);
        qb.push("actor = ")
            .push_bind(actor.to_string())
            .push(" COLLATE NOCASE");
    }
    if let Some(subject) = query.subject.as_deref() {
        sep(qb);
        qb.push("subject = ").push_bind(subject.to_string());
    }
    if let Some(machine) = query.machine.as_deref() {
        sep(qb);
        qb.push("(subject = ")
            .push_bind(machine.to_string())
            .push(" OR json_extract(metadata, '$.hostname') = ")
            .push_bind(machine.to_string())
            .push(")");
    }
    if let Some(provider) = query.provider.as_deref() {
        sep(qb);
        qb.push("json_extract(metadata, '$.provider') = ")
            .push_bind(provider.to_string())
            .push(" COLLATE NOCASE");
    }
    if let Some(serial) = query.serial.as_deref() {
        sep(qb);
        qb.push("json_extract(metadata, '$.serial') = ")
            .push_bind(serial.to_string());
    }
    if let Some(request_id) = query.request_id.as_deref() {
        sep(qb);
        qb.push("json_extract(metadata, '$.client.request_id') = ")
            .push_bind(request_id.to_string());
    }
    match query.result {
        Some(ResultFilter::Failure) => {
            sep(qb);
            qb.push(FAILURE_PREDICATE);
        }
        Some(ResultFilter::Success) => {
            sep(qb);
            qb.push("NOT ").push(FAILURE_PREDICATE);
        }
        None => {}
    }
    if let Some(since) = query.since_text() {
        sep(qb);
        qb.push("recorded_at >= ").push_bind(since);
    }
    if let Some(until) = query.until_text() {
        sep(qb);
        qb.push("recorded_at <= ").push_bind(until);
    }
    if let Some(after) = query.after_position {
        sep(qb);
        qb.push("chain_position > ").push_bind(after);
    }
    if let Some(before) = query.before_position {
        sep(qb);
        qb.push("chain_position < ").push_bind(before);
    }
}

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

    /// Search the log with the given filter, returning a bounded page.
    ///
    /// Read-only: builds a parameterized `SELECT` (no `UPDATE`/`DELETE` exists).
    /// Fetches `limit + 1` rows to detect whether more results remain without a
    /// separate count query.
    pub async fn search(&self, query: &AuditQuery) -> Result<AuditPage, AuditError> {
        let limit = query.effective_limit();

        let mut qb: QueryBuilder<'_, Sqlite> = QueryBuilder::new(
            "SELECT id, chain_position, event_type, actor, subject, metadata, recorded_at, \
             previous_hash, canonical_json, entry_hash FROM audit_log",
        );
        push_filters(&mut qb, query);
        qb.push(" ORDER BY chain_position ");
        qb.push(match query.order {
            Order::Ascending => "ASC",
            Order::Descending => "DESC",
        });
        qb.push(" LIMIT ").push_bind(limit + 1);

        let rows = qb
            .build_query_as::<AuditRow>()
            .fetch_all(&self.pool)
            .await?;

        let mut entries = rows
            .into_iter()
            .map(AuditEntry::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = entries.len() as i64 > limit;
        if has_more {
            entries.truncate(limit as usize);
        }
        Ok(AuditPage { entries, has_more })
    }

    /// Count entries matching the filter (ignores `limit`/`order`).
    pub async fn count(&self, query: &AuditQuery) -> Result<i64, AuditError> {
        let mut qb: QueryBuilder<'_, Sqlite> = QueryBuilder::new("SELECT COUNT(*) FROM audit_log");
        push_filters(&mut qb, query);
        let count: (i64,) = qb.build_query_as().fetch_one(&self.pool).await?;
        Ok(count.0)
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

    async fn seed_search_repo() -> AuditRepository {
        let repo = test_repo().await;
        repo.append_entry(
            NewAuditEntry::new("certificate.issued", "Octocat")
                .with_subject("web-01")
                .with_metadata(json!({ "serial": "0001", "provider": "github" })),
            at(1),
        )
        .await
        .expect("e1");
        repo.append_entry(
            NewAuditEntry::new("certificate.denied", "mallory")
                .with_subject("web-01")
                .with_metadata(json!({ "provider": "github" })),
            at(2),
        )
        .await
        .expect("e2");
        repo.append_entry(
            NewAuditEntry::new("machine.approved", "octocat")
                .with_subject("machine-1")
                .with_metadata(json!({ "hostname": "web-01", "provider": "keycloak" })),
            at(3),
        )
        .await
        .expect("e3");
        repo
    }

    #[tokio::test]
    async fn search_filters_by_prefix_and_orders_desc() {
        let repo = seed_search_repo().await;
        let page = repo
            .search(&AuditQuery {
                event_prefix: Some("certificate.".to_string()),
                ..AuditQuery::recent()
            })
            .await
            .expect("search");
        assert_eq!(page.entries.len(), 2);
        // Default order is descending by chain_position.
        assert_eq!(page.entries[0].chain_position, 2);
        assert_eq!(page.entries[1].chain_position, 1);
    }

    #[tokio::test]
    async fn search_actor_is_case_insensitive() {
        let repo = seed_search_repo().await;
        let page = repo
            .search(&AuditQuery {
                actor: Some("OCTOCAT".to_string()),
                ..AuditQuery::recent()
            })
            .await
            .expect("search");
        // certificate.issued (actor "Octocat") + machine.approved (actor "octocat").
        assert_eq!(page.entries.len(), 2);
    }

    #[tokio::test]
    async fn search_filters_by_result_failure() {
        let repo = seed_search_repo().await;
        let page = repo
            .search(&AuditQuery {
                result: Some(ResultFilter::Failure),
                ..AuditQuery::recent()
            })
            .await
            .expect("search");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].event_type, "certificate.denied");
    }

    #[tokio::test]
    async fn search_filters_by_provider_json_extract() {
        let repo = seed_search_repo().await;
        let page = repo
            .search(&AuditQuery {
                provider: Some("keycloak".to_string()),
                ..AuditQuery::recent()
            })
            .await
            .expect("search");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].event_type, "machine.approved");
    }

    #[tokio::test]
    async fn search_machine_matches_subject_or_hostname() {
        let repo = seed_search_repo().await;
        let page = repo
            .search(&AuditQuery {
                machine: Some("web-01".to_string()),
                ..AuditQuery::recent()
            })
            .await
            .expect("search");
        // Two subjects == web-01 plus one metadata.hostname == web-01.
        assert_eq!(page.entries.len(), 3);
    }

    #[tokio::test]
    async fn search_paginates_with_limit_and_cursor() {
        let repo = seed_search_repo().await;
        let page = repo
            .search(&AuditQuery {
                limit: 2,
                ..AuditQuery::recent()
            })
            .await
            .expect("search");
        assert_eq!(page.entries.len(), 2);
        assert!(page.has_more);

        // Ascending stream from position 1 onward.
        let stream = repo
            .search(&AuditQuery {
                order: Order::Ascending,
                after_position: Some(1),
                ..AuditQuery::recent()
            })
            .await
            .expect("stream");
        assert_eq!(stream.entries[0].chain_position, 2);
    }

    #[tokio::test]
    async fn search_filters_by_time_range_and_counts() {
        let repo = seed_search_repo().await;
        let q = AuditQuery {
            since: Some(at(2)),
            ..AuditQuery::recent()
        };
        let page = repo.search(&q).await.expect("search");
        assert_eq!(page.entries.len(), 2); // positions 2 and 3
        assert_eq!(repo.count(&q).await.expect("count"), 2);
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
