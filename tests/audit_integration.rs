//! Integration tests for the audit subsystem.

use mayfly_server::audit::{AuditRepository, GENESIS_PREVIOUS_HASH, NewAuditLogEntry};
use mayfly_server::db;

fn sample_entry(suffix: &str) -> NewAuditLogEntry {
    NewAuditLogEntry {
        serial: format!("serial-{suffix}"),
        username: format!("user-{suffix}"),
        github_login: format!("gh-{suffix}"),
        hostname: format!("host-{suffix}"),
        issued_at: format!("2026-06-24T12:00:{suffix}Z"),
        hashed_at: format!("2026-06-24T12:00:{suffix}Z"),
        ttl_seconds: 3600,
        requester_ip: Some("203.0.113.42".into()),
        cert_fingerprint: format!("fp-{suffix}"),
    }
}

#[tokio::test]
async fn repository_append_and_verify_end_to_end() {
    let pool = db::connect(":memory:").await.expect("connect");
    let repo = AuditRepository::new(pool);

    let first = repo.append_entry(sample_entry("01")).await.expect("first");
    let second = repo.append_entry(sample_entry("02")).await.expect("second");

    assert_eq!(first.chain_position, 1);
    assert_eq!(first.previous_hash, GENESIS_PREVIOUS_HASH);
    assert_eq!(second.previous_hash, first.entry_hash);

    let all = repo.fetch_all().await.expect("fetch all");
    assert_eq!(all.len(), 2);

    repo.verify_chain().await.expect("valid chain");
}
