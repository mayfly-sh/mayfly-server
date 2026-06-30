//! End-to-end tests for `POST /api/v1/admin/machines/enrollment-tokens`.
//!
//! GitHub is mocked with wiremock; the CA manager is the committed encrypted
//! test key. The full axum router is driven via `oneshot`, so the mint route is
//! exercised through its real GitHub-Bearer + deny-by-default authorization and
//! the real enrollment service. A minted token is then redeemed at
//! `/machines/enroll` to prove the operator → host enrollment path works
//! exactly as it does in the Docker integration environment (milestone 010C,
//! BL-007).

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeZone, Utc};
use mayfly_server::ca::CaManager;
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

fn agent_public_key() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .expect("gen")
        .public_key()
        .to_openssh()
        .expect("openssh")
}

async fn state_for(github_base: &str, access: AccessConfig) -> AppState {
    // A single pooled connection keeps the in-memory DB stable across the
    // sequential mint → enroll flow.
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
}

async fn mount_user(server: &MockServer, login: &str, id: u64) {
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "login": login,
            "id": id,
            "name": "Test Operator"
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
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn post(uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn enroll_request(token: &str, hostname: &str, public_key: &str) -> Request<Body> {
    post(
        "/api/v1/machines/enroll",
        None,
        json!({
            "enrollment_token": token,
            "hostname": hostname,
            "os": "linux",
            "arch": "x86_64",
            "agent_version": "0.1.0",
            "public_key": public_key,
        }),
    )
}

const MINT_URI: &str = "/api/v1/admin/machines/enrollment-tokens";

#[tokio::test]
async fn mint_then_enroll_succeeds() {
    let server = MockServer::start().await;
    mount_user(&server, "operator", 7).await;
    let state = state_for(&server.uri(), access_users(&["operator"])).await;

    // Operator mints a token.
    let (status, body) = call(
        &state,
        post(MINT_URI, Some("gho_token"), json!({ "ttl_seconds": 600 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = body["token"].as_str().expect("token").to_string();
    assert!(token.starts_with("mf_enroll_"), "token: {token}");
    assert_eq!(body["single_use"], true);
    assert!(body["id"].as_str().is_some());
    assert!(body["expires_at"].as_str().is_some());

    // The host redeems the minted token at the (unauthenticated) enroll route.
    let (status, body) = call(
        &state,
        enroll_request(&token, "managed-host-01", &agent_public_key()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["machine_id"].as_str().unwrap().starts_with("srv_"));
}

#[tokio::test]
async fn mint_defaults_single_use_and_ttl_when_body_omitted() {
    let server = MockServer::start().await;
    mount_user(&server, "operator", 7).await;
    let state = state_for(&server.uri(), access_users(&["operator"])).await;

    // No body at all: defaults apply (single_use = true, default TTL).
    let (status, body) = call(&state, post(MINT_URI, Some("gho_token"), json!({}))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["single_use"], true);
    assert!(body["token"].as_str().unwrap().starts_with("mf_enroll_"));
}

#[tokio::test]
async fn mint_requires_authentication() {
    let server = MockServer::start().await;
    mount_user(&server, "operator", 7).await;
    let state = state_for(&server.uri(), access_users(&["operator"])).await;

    let (status, _) = call(&state, post(MINT_URI, None, json!({}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mint_denied_for_unauthorized_user() {
    let server = MockServer::start().await;
    // The caller resolves to "intruder", who is not on the allowlist.
    mount_user(&server, "intruder", 99).await;
    let state = state_for(&server.uri(), access_users(&["operator"])).await;

    let (status, _) = call(&state, post(MINT_URI, Some("gho_token"), json!({}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The denial was audited; no token was minted.
    let events: Vec<String> =
        sqlx::query_as::<_, (String,)>("SELECT event_type FROM audit_log ORDER BY chain_position")
            .fetch_all(state.db())
            .await
            .expect("audit")
            .into_iter()
            .map(|r| r.0)
            .collect();
    assert!(events.contains(&"ca.admin_denied".to_string()));
    assert!(!events.contains(&"machine.enrollment_token.minted".to_string()));
}

#[tokio::test]
async fn mint_is_audited_without_leaking_the_token() {
    let server = MockServer::start().await;
    mount_user(&server, "operator", 7).await;
    let state = state_for(&server.uri(), access_users(&["operator"])).await;

    let (status, body) = call(&state, post(MINT_URI, Some("gho_token"), json!({}))).await;
    assert_eq!(status, StatusCode::CREATED);
    let token = body["token"].as_str().unwrap().to_string();
    let id = body["id"].as_str().unwrap().to_string();

    let row: (String, String, Option<String>, String) = sqlx::query_as(
        "SELECT event_type, actor, subject, metadata FROM audit_log \
         ORDER BY chain_position DESC LIMIT 1",
    )
    .fetch_one(state.db())
    .await
    .expect("audit row");
    assert_eq!(row.0, "machine.enrollment_token.minted");
    assert_eq!(row.1, "operator");
    assert_eq!(row.2.as_deref(), Some(id.as_str()));
    // The plaintext token must never appear in the audit metadata.
    assert!(!row.3.contains(&token));
    assert!(!row.3.contains("mf_enroll_"));
}
