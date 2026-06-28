//! End-to-end tests for `POST /api/v1/machines/enroll`.
//!
//! The full axum router is driven via `oneshot`. The real CA is loaded from the
//! encrypted test key under `testdata/` so the response carries a genuine
//! server identity. Tokens are minted through the public service API, exactly
//! as an operator would.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeDelta, TimeZone, Utc};
use mayfly_server::ca::CaManager;
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::Config;
use mayfly_server::db;
use mayfly_server::machines::{token, EnrollmentService};
use mayfly_server::routes::build_router;
use mayfly_server::state::AppState;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use tower::ServiceExt;

const CA_PASSPHRASE: &str = "mayfly-test-passphrase";

fn ca_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
}

fn agent_public_key() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .expect("gen")
        .public_key()
        .to_openssh()
        .expect("openssh")
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ))
}

/// Build an in-memory-backed app state with the test CA, capped at `max_conns`
/// pooled connections. A single connection (`max_conns == 1`) keeps the
/// in-memory database alive and serializes concurrent requests at the pool.
async fn state_with_pool(clock: Arc<TestClock>, max_conns: u32) -> AppState {
    let options = SqliteConnectOptions::from_str(":memory:")
        .expect("opts")
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5));
    let pool: SqlitePool = SqlitePoolOptions::new()
        .max_connections(max_conns)
        .connect_with(options)
        .await
        .expect("pool");
    db::migrate(&pool).await.expect("migrate");

    let mut config = Config::default();
    config.server.tls.enabled = false;

    let dyn_clock: Arc<dyn Clock> = clock;
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
    AppState::new(config, pool, dyn_clock).with_ca(ca)
}

async fn state(clock: Arc<TestClock>) -> AppState {
    // One connection keeps the in-memory DB stable across the sequential
    // mint → enroll → assert flow.
    state_with_pool(clock, 1).await
}

/// Mint a token through the service, returning its one-time plaintext.
async fn mint_token(state: &AppState, single_use: bool) -> String {
    let server_identity = state
        .ca()
        .expect("ca")
        .primary_public_key()
        .expect("ca public key");
    let service = EnrollmentService::sqlite(state.db().clone(), state.clock_arc(), server_identity);
    service
        .create_enrollment_token("admin", TimeDelta::hours(1), single_use)
        .await
        .expect("mint token")
        .plaintext
}

fn enroll_request(token: &str, hostname: &str, public_key: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/machines/enroll")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enrollment_token": token,
                "hostname": hostname,
                "os": "linux",
                "arch": "x86_64",
                "agent_version": "0.1.0",
                "public_key": public_key,
            })
            .to_string(),
        ))
        .unwrap()
}

async fn call(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = build_router(state)
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    // The success/typed-error paths return JSON; axum's built-in extractor
    // rejection (malformed body) returns plain text, so fall back to Null.
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn machine_count(state: &AppState) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM machines")
        .fetch_one(state.db())
        .await
        .expect("count")
        .0
}

async fn token_used(state: &AppState, plaintext: &str) -> bool {
    let hash = token::hash_token(plaintext);
    let used: (Option<String>,) =
        sqlx::query_as("SELECT used_at FROM machine_enrollment_tokens WHERE token_hash = ?")
            .bind(hash)
            .fetch_one(state.db())
            .await
            .expect("token row");
    used.0.is_some()
}

#[tokio::test]
async fn valid_enrollment_succeeds() {
    let state = state(fixed_clock()).await;
    let tok = mint_token(&state, true).await;
    let probe = state.clone();

    let (status, body) = call(state, enroll_request(&tok, "web-01", &agent_public_key())).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["machine_id"].as_str().unwrap().starts_with("srv_"));
    assert_eq!(body["heartbeat_interval"], 60);
    // sync_interval is jittered per host within ±10% of the configured base
    // (300s) so the fleet does not poll in lockstep.
    let sync_interval = body["sync_interval"].as_u64().expect("sync_interval");
    assert!(
        (270..=330).contains(&sync_interval),
        "sync_interval {sync_interval} outside jitter window"
    );
    assert!(body["server_identity"]
        .as_str()
        .unwrap()
        .starts_with("ssh-ed25519 "));

    assert_eq!(machine_count(&probe).await, 1);
    assert!(token_used(&probe, &tok).await);
}

#[tokio::test]
async fn audit_event_written_on_enroll() {
    let state = state(fixed_clock()).await;
    let tok = mint_token(&state, true).await;
    let probe = state.clone();

    let (status, body) = call(state, enroll_request(&tok, "web-01", &agent_public_key())).await;
    assert_eq!(status, StatusCode::OK);
    let machine_id = body["machine_id"].as_str().unwrap().to_string();

    let row: (String, String, Option<String>) = sqlx::query_as(
        "SELECT event_type, actor, subject FROM audit_log ORDER BY chain_position DESC LIMIT 1",
    )
    .fetch_one(probe.db())
    .await
    .expect("audit row");
    assert_eq!(row.0, "machine.enrolled");
    assert_eq!(row.1, "system");
    assert_eq!(row.2.as_deref(), Some(machine_id.as_str()));
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let tok = mint_token(&state, true).await;
    // Move past the one-hour TTL before the request is served.
    clock.advance(TimeDelta::hours(2));

    let (status, body) = call(state, enroll_request(&tok, "web-01", &agent_public_key())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "TOKEN_EXPIRED");
}

#[tokio::test]
async fn invalid_token_is_rejected() {
    let state = state(fixed_clock()).await;
    let (status, body) = call(
        state,
        enroll_request("mf_enroll_doesnotexist", "web-01", &agent_public_key()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "TOKEN_INVALID");
}

#[tokio::test]
async fn malformed_token_is_rejected() {
    let state = state(fixed_clock()).await;
    let (status, body) = call(
        state,
        enroll_request("not-a-real-token", "web-01", &agent_public_key()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "TOKEN_INVALID");
}

#[tokio::test]
async fn already_used_token_is_rejected() {
    let state = state(fixed_clock()).await;
    let tok = mint_token(&state, true).await;

    let (status, _) = call(
        state.clone(),
        enroll_request(&tok, "web-01", &agent_public_key()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(state, enroll_request(&tok, "web-02", &agent_public_key())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "TOKEN_ALREADY_USED");
}

#[tokio::test]
async fn duplicate_hostname_is_rejected() {
    let state = state(fixed_clock()).await;
    let tok1 = mint_token(&state, true).await;
    let tok2 = mint_token(&state, true).await;

    let (status, _) = call(
        state.clone(),
        enroll_request(&tok1, "web-01", &agent_public_key()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(state, enroll_request(&tok2, "web-01", &agent_public_key())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "HOST_ALREADY_ENROLLED");
}

#[tokio::test]
async fn duplicate_public_key_is_rejected() {
    let state = state(fixed_clock()).await;
    let tok1 = mint_token(&state, true).await;
    let tok2 = mint_token(&state, true).await;
    let key = agent_public_key();

    let (status, _) = call(state.clone(), enroll_request(&tok1, "web-01", &key)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(state, enroll_request(&tok2, "web-02", &key)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "PUBLIC_KEY_ALREADY_EXISTS");
}

#[tokio::test]
async fn invalid_public_key_is_rejected() {
    let state = state(fixed_clock()).await;
    let tok = mint_token(&state, true).await;

    let (status, body) = call(state, enroll_request(&tok, "web-01", "not a key")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "PUBLIC_KEY_INVALID");
}

#[tokio::test]
async fn malformed_request_is_rejected() {
    let state = state(fixed_clock()).await;
    // Syntactically broken JSON => the JSON extractor rejects it as 400.
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/machines/enroll")
        .header("content-type", "application/json")
        .body(Body::from("{ this is not valid json"))
        .unwrap();
    let (status, _) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Well-formed JSON missing required fields is also rejected (422).
    let missing_fields = Request::builder()
        .method("POST")
        .uri("/api/v1/machines/enroll")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "hostname": "web-01" }).to_string()))
        .unwrap();
    let (status, _) = call(state, missing_fields).await;
    assert!(status.is_client_error(), "expected 4xx, got {status}");
}

#[tokio::test]
async fn concurrent_enrollment_consumes_token_exactly_once() {
    // A single pooled connection serializes the two requests deterministically:
    // whoever acquires the connection first enrolls; the other observes the
    // consumed single-use token and is rejected.
    let state = state_with_pool(fixed_clock(), 1).await;
    let tok = mint_token(&state, true).await;

    let first = call(
        state.clone(),
        enroll_request(&tok, "web-01", &agent_public_key()),
    );
    let second = call(
        state.clone(),
        enroll_request(&tok, "web-02", &agent_public_key()),
    );
    let ((status_a, _), (status_b, _)) = tokio::join!(first, second);

    // Exactly one success and one already-used rejection.
    let statuses: BTreeSet<u16> = [status_a.as_u16(), status_b.as_u16()].into_iter().collect();
    assert_eq!(
        statuses,
        BTreeSet::from([StatusCode::OK.as_u16(), StatusCode::CONFLICT.as_u16()]),
        "expected exactly one 200 and one 409, got {statuses:?}"
    );

    // Exactly one machine was created and the token is consumed.
    assert_eq!(machine_count(&state).await, 1);
    assert!(token_used(&state, &tok).await);
}
