//! End-to-end tests for the operational console admin API (013C).
//!
//! GitHub is mocked with wiremock; the CA manager is constructed from the
//! committed encrypted test key. Audit entries are seeded directly through the
//! `AuditService` (the same append-only path production uses) so the read-only
//! search/health endpoints have deterministic data, then exercised through the
//! full axum router via `oneshot`.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeZone, Utc};
use mayfly_server::audit::NewAuditEntry;
use mayfly_server::bundle::Ed25519BundleSigner;
use mayfly_server::ca::CaManager;
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::{AccessConfig, Config};
use mayfly_server::db;
use mayfly_server::github::RealGitHubClient;
use mayfly_server::routes::build_router;
use mayfly_server::state::AppState;
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CA_PASSPHRASE: &str = "mayfly-test-passphrase";

fn ca_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ))
}

fn access_users(users: &[&str]) -> AccessConfig {
    AccessConfig {
        allowed_users: users.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

async fn state_for(github_base: &str, access: AccessConfig) -> AppState {
    let pool = db::connect(":memory:").await.expect("db");
    let mut config = Config::default();
    config.server.tls.enabled = false;
    config.access = access;

    let github = Arc::new(RealGitHubClient::new(
        "client-id".into(),
        "client-secret".into(),
        "read:user".into(),
        github_base.to_string(),
        github_base.to_string(),
    ));
    let dyn_clock: Arc<dyn Clock> = fixed_clock();
    let ca = Arc::new(
        CaManager::from_single_encrypted_file(
            &ca_key_path(),
            CA_PASSPHRASE,
            "mayfly-ca",
            dyn_clock.clone(),
        )
        .await
        .expect("load ca"),
    );
    AppState::new(config, pool, dyn_clock)
        .with_github(github)
        .with_ca(ca)
        .with_bundle_signer(Arc::new(Ed25519BundleSigner::from_seed(&[7u8; 32])))
}

async fn mount_user(server: &MockServer, login: &str, id: u64) {
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "login": login,
            "id": id,
            "name": "Test User"
        })))
        .mount(server)
        .await;
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = build_router(state.clone())
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json")
    };
    (status, value)
}

fn get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::empty()).unwrap()
}

/// Seed a representative spread of audit events through the real append path.
async fn seed_audit(state: &AppState) {
    let audit = state.audit();
    audit
        .append_audit_event(
            NewAuditEntry::new("certificate.issued", "octocat")
                .with_subject("web-01")
                .with_metadata(json!({
                    "serial": "0001",
                    "provider": "github",
                    "client": { "request_id": "req-aaa" },
                })),
        )
        .await
        .expect("seed cert issued");
    audit
        .append_audit_event(
            NewAuditEntry::new("certificate.denied", "mallory")
                .with_subject("web-01")
                .with_metadata(json!({ "reason": "not allowed", "provider": "github" })),
        )
        .await
        .expect("seed cert denied");
    audit
        .append_audit_event(
            NewAuditEntry::new("auth.identity_lookup", "octocat")
                .with_metadata(json!({ "provider": "github" })),
        )
        .await
        .expect("seed auth");
    audit
        .append_audit_event(
            NewAuditEntry::new("machine.approved", "octocat")
                .with_subject("machine-1")
                .with_metadata(json!({ "hostname": "web-01", "provider": "github" })),
        )
        .await
        .expect("seed machine");
}

#[tokio::test]
async fn audit_search_denies_unauthorized_and_audits_the_denial() {
    let server = MockServer::start().await;
    mount_user(&server, "intruder", 99).await;
    // Empty allowlist denies everyone (deny-by-default).
    let state = state_for(&server.uri(), access_users(&[])).await;

    let (status, _) = call(&state, get("/api/v1/admin/audit", Some("tok"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The denial is the only write these read endpoints perform.
    let page = state
        .audit()
        .search(&mayfly_server::audit::AuditQuery {
            event_type: Some("ops.admin_denied".to_string()),
            ..mayfly_server::audit::AuditQuery::recent()
        })
        .await
        .expect("search");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].subject.as_deref(), Some("ops.audit"));
}

#[tokio::test]
async fn audit_search_filters_by_event_type_and_result() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_audit(&state).await;

    // Prefix filter: all certificate events.
    let (status, body) = call(
        &state,
        get("/api/v1/admin/audit?event_type=certificate.", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 2);

    // Result filter: only failures (the denial).
    let (status, body) = call(
        &state,
        get(
            "/api/v1/admin/audit?event_type=certificate.&result=failure",
            Some("tok"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert_eq!(body["entries"][0]["event_type"], "certificate.denied");
    assert_eq!(body["entries"][0]["result"], "failure");
}

#[tokio::test]
async fn audit_search_filters_by_metadata_fields() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_audit(&state).await;

    // serial → metadata.serial.
    let (status, body) = call(&state, get("/api/v1/admin/audit?serial=0001", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert_eq!(body["entries"][0]["event_type"], "certificate.issued");

    // request_id → metadata.client.request_id.
    let (status, body) = call(
        &state,
        get("/api/v1/admin/audit?request_id=req-aaa", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);

    // machine → subject OR metadata.hostname.
    let (status, body) = call(
        &state,
        get("/api/v1/admin/audit?machine=web-01", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // certificate.issued + certificate.denied (subject) + machine.approved (hostname).
    assert_eq!(body["count"], 3);
}

#[tokio::test]
async fn audit_search_paginates_and_streams() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_audit(&state).await; // 4 entries

    // Page 1: newest-first, limit 2 → has_more.
    let (status, body) = call(&state, get("/api/v1/admin/audit?limit=2", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 2);
    assert_eq!(body["has_more"], true);
    assert_eq!(body["order"], "desc");

    // Stream from the beginning (ascending, after=0) returns oldest first.
    let (status, body) = call(
        &state,
        get("/api/v1/admin/audit/stream?after=0&limit=2", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["order"], "asc");
    assert_eq!(body["entries"][0]["position"], 1);
    assert_eq!(body["has_more"], true);
    assert_eq!(body["last_position"], 2);
}

#[tokio::test]
async fn health_reports_operational_rollup() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_audit(&state).await;

    let (status, body) = call(&state, get("/api/v1/admin/health", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["status"].is_string());
    assert_eq!(body["certificates"]["issued"], 1);
    assert_eq!(body["certificates"]["denied"], 1);
    assert_eq!(body["audit"]["verified"], true);
    assert_eq!(body["audit"]["entries"], 4);
    assert!(body["bundle"]["configured"].as_bool().unwrap());
    assert_eq!(body["authentication"]["total"], 1);
}

#[tokio::test]
async fn status_reports_system_facts() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;

    let (status, body) = call(&state, get("/api/v1/admin/status", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["database"], "ok");
    assert_eq!(body["certificate_authority"]["configured"], true);
    assert!(body["providers"]
        .as_array()
        .unwrap()
        .contains(&json!("github")));
}

#[tokio::test]
async fn metrics_record_requests() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;

    // Drive a couple of requests so the collector has data.
    let _ = call(&state, get("/api/v1/admin/status", Some("tok"))).await;
    let _ = call(&state, get("/api/v1/admin/health", Some("tok"))).await;

    let (status, body) = call(&state, get("/api/v1/admin/metrics", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total_requests"].as_u64().unwrap() >= 2);
    let routes = body["routes"].as_array().unwrap();
    assert!(
        routes
            .iter()
            .any(|r| r["route"].as_str().unwrap().contains("/admin/status")),
        "metrics should track the status route template: {routes:?}"
    );
}
