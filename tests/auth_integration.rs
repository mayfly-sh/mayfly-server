//! End-to-end tests for the GitHub Device Flow auth endpoints.
//!
//! GitHub is mocked with wiremock; the full axum router is driven via
//! `oneshot`. No real GitHub calls are made.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeZone, Utc};
use mayfly_server::clock::TestClock;
use mayfly_server::config::Config;
use mayfly_server::db;
use mayfly_server::github::RealGitHubClient;
use mayfly_server::routes::build_router;
use mayfly_server::state::AppState;
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn state_for(github_base: &str) -> AppState {
    let pool = db::connect(":memory:").await.expect("db");
    let mut config = Config::default();
    config.server.tls.enabled = false;
    let clock = Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ));
    let github = Arc::new(RealGitHubClient::new(
        "client-id".into(),
        "client-secret".into(),
        "read:user".into(),
        github_base.to_string(),
        github_base.to_string(),
    ));
    AppState::new(config, pool, clock).with_github(github)
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

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn device_start_returns_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dc-123",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5
        })))
        .mount(&server)
        .await;

    let state = state_for(&server.uri()).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/device/start")
        .body(Body::empty())
        .unwrap();

    let (status, body) = call(state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_code"], "ABCD-EFGH");
    assert_eq!(body["interval"], 5);
}

#[tokio::test]
async fn device_poll_approved_returns_token_and_audits() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gho_secret",
            "token_type": "bearer",
            "scope": "read:user"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "login": "vasugarg",
            "id": 12345,
            "name": "Vasu Garg"
        })))
        .mount(&server)
        .await;

    let state = state_for(&server.uri()).await;
    let audit_state = state.clone();
    let req = post_json("/api/v1/auth/device/poll", json!({ "device_code": "dc-123" }));

    let (status, body) = call(state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "approved");
    assert_eq!(body["access_token"], "gho_secret");

    let events = audit_events(&audit_state).await;
    assert_eq!(events, vec![("auth.device_authorized".to_string(), "vasugarg".to_string())]);
}

#[tokio::test]
async fn device_poll_pending_is_not_audited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "error": "authorization_pending" })),
        )
        .mount(&server)
        .await;

    let state = state_for(&server.uri()).await;
    let audit_state = state.clone();
    let req = post_json("/api/v1/auth/device/poll", json!({ "device_code": "dc-123" }));

    let (status, body) = call(state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "pending");
    assert!(body.get("access_token").is_none());

    assert!(audit_events(&audit_state).await.is_empty());
}

#[tokio::test]
async fn device_poll_denied_is_not_audited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "error": "access_denied" })))
        .mount(&server)
        .await;

    let state = state_for(&server.uri()).await;
    let audit_state = state.clone();
    let req = post_json("/api/v1/auth/device/poll", json!({ "device_code": "dc-123" }));

    let (status, body) = call(state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "denied");
    assert!(audit_events(&audit_state).await.is_empty());
}

#[tokio::test]
async fn whoami_returns_identity_and_audits() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "login": "vasugarg",
            "id": 12345,
            "name": "Vasu Garg",
            "email": "vasu@example.com"
        })))
        .mount(&server)
        .await;

    let state = state_for(&server.uri()).await;
    let audit_state = state.clone();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/whoami")
        .header("authorization", "Bearer gho_secret")
        .body(Body::empty())
        .unwrap();

    let (status, body) = call(state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["github_login"], "vasugarg");
    assert_eq!(body["github_id"], 12345);
    assert_eq!(body["email"], "vasu@example.com");

    let events = audit_events(&audit_state).await;
    assert_eq!(events, vec![("auth.identity_lookup".to_string(), "vasugarg".to_string())]);
}

#[tokio::test]
async fn whoami_missing_bearer_is_unauthorized() {
    let server = MockServer::start().await;
    let state = state_for(&server.uri()).await;
    let audit_state = state.clone();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/whoami")
        .body(Body::empty())
        .unwrap();

    let (status, _body) = call(state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(audit_events(&audit_state).await.is_empty());
}

#[tokio::test]
async fn whoami_invalid_token_is_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let state = state_for(&server.uri()).await;
    let audit_state = state.clone();
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/whoami")
        .header("authorization", "Bearer bad")
        .body(Body::empty())
        .unwrap();

    let (status, _body) = call(state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(audit_events(&audit_state).await.is_empty());
}
