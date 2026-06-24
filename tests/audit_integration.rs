//! Integration tests for the audit subsystem over the real DB layer.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use mayfly_server::audit::{AuditService, AuditVerificationResult, NewAuditEntry, GENESIS_PREVIOUS_HASH};
use mayfly_server::clock::TestClock;
use mayfly_server::db;
use serde_json::json;

async fn service() -> AuditService {
    let pool = db::connect(":memory:").await.expect("connect");
    let clock = Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ));
    AuditService::from_pool(pool, clock)
}

fn event(suffix: &str) -> NewAuditEntry {
    NewAuditEntry::new("certificate.issued", format!("octocat-{suffix}"))
        .with_subject(format!("web-{suffix}"))
        .with_metadata(json!({ "serial": suffix, "ttl_seconds": 3600 }))
}

#[tokio::test]
async fn append_verify_and_tip_end_to_end() {
    let service = service().await;

    let first = service.append_audit_event(event("01")).await.expect("first");
    let second = service.append_audit_event(event("02")).await.expect("second");

    assert_eq!(first.chain_position, 1);
    assert_eq!(first.previous_hash, GENESIS_PREVIOUS_HASH);
    assert_eq!(second.previous_hash, first.entry_hash);

    let result = service.verify_chain().await.expect("verify");
    assert!(matches!(
        result,
        AuditVerificationResult::Valid { entries_verified: 2 }
    ));

    let tip = service.get_tip().await.expect("tip").expect("some");
    assert_eq!(tip.chain_position, 2);
    assert_eq!(tip.entry_hash, second.entry_hash);
}

#[tokio::test]
async fn append_only_is_enforced_by_storage() {
    // The migration installs BEFORE UPDATE / BEFORE DELETE triggers; in-band
    // mutation must be rejected outright regardless of the service API.
    let pool = db::connect(":memory:").await.expect("connect");
    let clock = Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ));
    let svc = AuditService::from_pool(pool.clone(), clock);
    svc.append_audit_event(event("01")).await.expect("append");

    let update = sqlx::query("UPDATE audit_log SET actor = 'x'")
        .execute(&pool)
        .await;
    assert!(update.is_err(), "updates must be rejected");

    let delete = sqlx::query("DELETE FROM audit_log")
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "deletes must be rejected");
}
