//! High-level audit API: stamps events, exposes the tip, and verifies the chain.
//!
//! The service is the seam other subsystems (certificate issuance, OAuth, …)
//! depend on. It owns the [`Clock`] so timestamps are deterministic in tests
//! and never read directly from `Utc::now()` in business logic.

use crate::audit::model::{AuditTip, AuditVerificationResult, NewAuditEntry};
use crate::audit::query::{AuditPage, AuditQuery};
use crate::audit::repository::AuditRepository;
use crate::audit::verifier;
use crate::clock::Clock;
use crate::errors::AuditError;
use std::sync::Arc;

/// Orchestrates audit logging over an [`AuditRepository`].
#[derive(Clone)]
pub struct AuditService {
    repository: AuditRepository,
    clock: Arc<dyn Clock>,
}

impl AuditService {
    /// Build a service from a repository and a clock.
    pub fn new(repository: AuditRepository, clock: Arc<dyn Clock>) -> Self {
        Self { repository, clock }
    }

    /// Convenience constructor from a connection pool.
    pub fn from_pool(pool: sqlx::SqlitePool, clock: Arc<dyn Clock>) -> Self {
        Self::new(AuditRepository::new(pool), clock)
    }

    /// Record a new audit event, stamping `recorded_at` from the clock.
    pub async fn append_audit_event(
        &self,
        event: NewAuditEntry,
    ) -> Result<crate::audit::model::AuditEntry, AuditError> {
        let recorded_at = self.clock.now();
        self.repository.append_entry(event, recorded_at).await
    }

    /// Verify the full chain. A [`AuditVerificationResult::Broken`] result is
    /// logged on the dedicated security target before being returned, so tamper
    /// detection is always observable even if the caller ignores the value.
    pub async fn verify_chain(&self) -> Result<AuditVerificationResult, AuditError> {
        let entries = self.repository.list_entries().await?;
        let result = verifier::verify_chain(&entries);

        if let AuditVerificationResult::Broken { position, reason } = &result {
            tracing::error!(
                target: "mayfly::security",
                position,
                reason = %reason,
                "audit chain integrity violation detected"
            );
        }

        Ok(result)
    }

    /// Search the audit log (read-only) with the given filter.
    pub async fn search(&self, query: &AuditQuery) -> Result<AuditPage, AuditError> {
        self.repository.search(query).await
    }

    /// Count entries matching the filter (read-only).
    pub async fn count(&self, query: &AuditQuery) -> Result<i64, AuditError> {
        self.repository.count(query).await
    }

    /// Return the current head of the chain, or `None` if the log is empty.
    pub async fn get_tip(&self) -> Result<Option<AuditTip>, AuditError> {
        Ok(self.repository.latest_entry().await?.map(|entry| AuditTip {
            chain_position: entry.chain_position,
            entry_hash: entry.entry_hash,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::db;
    use chrono::{SecondsFormat, TimeZone, Utc};
    use serde_json::json;

    async fn test_service() -> (AuditService, Arc<TestClock>) {
        let pool = db::connect(":memory:").await.expect("connect");
        let clock = Arc::new(TestClock::new(
            Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
        ));
        let service = AuditService::from_pool(pool, clock.clone());
        (service, clock)
    }

    fn event(suffix: &str) -> NewAuditEntry {
        NewAuditEntry::new("test.event", format!("actor-{suffix}"))
            .with_metadata(json!({ "suffix": suffix }))
    }

    #[tokio::test]
    async fn append_stamps_recorded_at_from_clock() {
        let (service, clock) = test_service().await;
        let entry = service
            .append_audit_event(event("01"))
            .await
            .expect("append");

        assert_eq!(
            entry
                .recorded_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            clock.now().to_rfc3339_opts(SecondsFormat::Millis, true)
        );
        assert_eq!(entry.chain_position, 1);
    }

    #[tokio::test]
    async fn get_tip_tracks_latest_entry() {
        let (service, _clock) = test_service().await;
        assert!(service.get_tip().await.expect("tip").is_none());

        service
            .append_audit_event(event("01"))
            .await
            .expect("first");
        let second = service
            .append_audit_event(event("02"))
            .await
            .expect("second");

        let tip = service.get_tip().await.expect("tip").expect("some");
        assert_eq!(tip.chain_position, 2);
        assert_eq!(tip.entry_hash, second.entry_hash);
    }

    #[tokio::test]
    async fn verify_chain_reports_valid_then_broken() {
        let (service, _clock) = test_service().await;
        service
            .append_audit_event(event("01"))
            .await
            .expect("first");
        service
            .append_audit_event(event("02"))
            .await
            .expect("second");

        assert!(service.verify_chain().await.expect("verify").is_valid());

        sqlx::raw_sql("DROP TRIGGER audit_log_no_update; DROP TRIGGER audit_log_no_delete;")
            .execute(service.repository.pool())
            .await
            .expect("drop triggers");
        sqlx::query("UPDATE audit_log SET actor = 'intruder' WHERE chain_position = 2")
            .execute(service.repository.pool())
            .await
            .expect("tamper");

        assert!(matches!(
            service.verify_chain().await.expect("verify"),
            AuditVerificationResult::Broken { position: 2, .. }
        ));
    }
}
