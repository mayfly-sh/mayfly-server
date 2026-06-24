//! End-to-end tests for authorization + certificate issuance/validation.
//!
//! GitHub is mocked with wiremock; the real CA is loaded from the encrypted
//! test key under `testdata/`. The full axum router is driven via `oneshot`.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeDelta, TimeZone, Utc};
use mayfly_server::ca::CaService;
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::{AccessConfig, Config};
use mayfly_server::db;
use mayfly_server::github::RealGitHubClient;
use mayfly_server::routes::build_router;
use mayfly_server::state::AppState;
use serde_json::{json, Value};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CA_PASSPHRASE: &str = "mayfly-test-passphrase";

fn ca_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
}

fn user_public_key() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .expect("gen")
        .public_key()
        .to_openssh()
        .expect("openssh")
}

fn access_users(users: &[&str]) -> AccessConfig {
    AccessConfig {
        allowed_users: users.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

async fn state_for(github_base: &str, clock: Arc<TestClock>, access: AccessConfig) -> AppState {
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
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let ca = Arc::new(
        CaService::load(&ca_key_path(), CA_PASSPHRASE, "mayfly-ca", dyn_clock.clone())
            .expect("load ca"),
    );

    AppState::new(config, pool, dyn_clock)
        .with_github(github)
        .with_ca(ca)
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

async fn call(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = build_router(state).oneshot(request).await.expect("response");
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

async fn audit_events(state: &AppState) -> Vec<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT event_type, actor FROM audit_log ORDER BY chain_position ASC",
    )
    .fetch_all(state.db())
    .await
    .expect("audit query")
}

fn issue_request(public_key: &str, ttl: u32) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/issue")
        .header("content-type", "application/json")
        .header("authorization", "Bearer gho_token")
        .body(Body::from(
            json!({ "public_key": public_key, "hostname": "web-01", "ttl_seconds": ttl })
                .to_string(),
        ))
        .unwrap()
}

fn validate_request(certificate: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/api/v1/certificates/validate")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "certificate": certificate }).to_string()))
        .unwrap()
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ))
}

#[tokio::test]
async fn certificate_issuance_success() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 12345).await;

    let state = state_for(&server.uri(), fixed_clock(), access_users(&["vasugarg"])).await;
    let (status, body) = call(state, issue_request(&user_public_key(), 300)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["principal"], "vasugarg");
    assert_eq!(body["ttl_seconds"], 300);
    assert!(body["certificate"]
        .as_str()
        .unwrap()
        .contains("ssh-ed25519-cert-v01@openssh.com"));
    assert!(body["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
}

#[tokio::test]
async fn audit_event_written_on_issue() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 12345).await;

    let state = state_for(&server.uri(), fixed_clock(), access_users(&["vasugarg"])).await;
    let audit_state = state.clone();
    let (status, _) = call(state, issue_request(&user_public_key(), 300)).await;
    assert_eq!(status, StatusCode::OK);

    let events = audit_events(&audit_state).await;
    assert_eq!(
        events,
        vec![("certificate.issued".to_string(), "vasugarg".to_string())]
    );
}

#[tokio::test]
async fn certificate_issuance_denied() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 12345).await;

    // Empty allowlist => deny everyone.
    let state = state_for(&server.uri(), fixed_clock(), AccessConfig::default()).await;
    let audit_state = state.clone();
    let (status, body) = call(state, issue_request(&user_public_key(), 300)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");
    // The detailed reason is not leaked to the client.
    assert_eq!(body["error"]["message"], "access denied");

    // The denial is audited.
    let events = audit_events(&audit_state).await;
    assert_eq!(
        events,
        vec![("certificate.denied".to_string(), "vasugarg".to_string())]
    );
}

#[tokio::test]
async fn certificate_issuance_missing_bearer_is_unauthorized() {
    let server = MockServer::start().await;
    let state = state_for(&server.uri(), fixed_clock(), access_users(&["vasugarg"])).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/issue")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "public_key": "x", "hostname": "h", "ttl_seconds": 300 }).to_string(),
        ))
        .unwrap();

    let (status, _) = call(state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn certificate_validate_success() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 12345).await;
    let clock = fixed_clock();
    let state = state_for(&server.uri(), clock.clone(), access_users(&["vasugarg"])).await;

    // Issue a certificate, then validate it at the same clock time.
    let (status, issued) = call(state.clone(), issue_request(&user_public_key(), 300)).await;
    assert_eq!(status, StatusCode::OK);
    let certificate = issued["certificate"].as_str().unwrap().to_string();

    let (status, body) = call(state, validate_request(&certificate)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);
    assert_eq!(body["issued_by_this_ca"], true);
    assert!(body.get("reason").is_none() || body["reason"].is_null());
    assert_eq!(body["principals"][0], "vasugarg");
}

#[tokio::test]
async fn certificate_validate_expired() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 12345).await;
    let clock = fixed_clock();
    let state = state_for(&server.uri(), clock.clone(), access_users(&["vasugarg"])).await;

    let (status, issued) = call(state.clone(), issue_request(&user_public_key(), 300)).await;
    assert_eq!(status, StatusCode::OK);
    let certificate = issued["certificate"].as_str().unwrap().to_string();

    // Advance well past the 300s TTL, then validate.
    clock.advance(TimeDelta::seconds(10_000));

    let (status, body) = call(state, validate_request(&certificate)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], false);
    assert_eq!(body["issued_by_this_ca"], true);
    assert_eq!(body["reason"], "certificate has expired");
}
