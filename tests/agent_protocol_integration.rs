//! End-to-end tests for the authenticated agent protocol:
//! `POST /api/v1/agent/heartbeat` (Ed25519-signed) and `GET /api/v1/servers`
//! (GitHub bearer + authz, derived liveness).
//!
//! Requests are signed exactly as a real agent would sign them, using the
//! server's own `agentauth::signing` helpers over a freshly generated Ed25519
//! key whose public half is enrolled first. All time comes from a `TestClock`,
//! so liveness transitions are exercised without sleeping.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeDelta, TimeZone, Utc};
use mayfly_server::agentauth::signing;
use mayfly_server::ca::CaManager;
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::Config;
use mayfly_server::db;
use mayfly_server::github::models::{DeviceAuthorization, DeviceTokenOutcome, GitHubUser};
use mayfly_server::github::{GitHubClient, GitHubError};
use mayfly_server::machines::EnrollmentService;
use mayfly_server::routes::build_router;
use mayfly_server::state::AppState;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use ssh_key::private::KeypairData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use tower::ServiceExt;

const CA_PASSPHRASE: &str = "mayfly-test-passphrase";
const HEARTBEAT_PATH: &str = "/api/v1/agent/heartbeat";
const OPERATOR: &str = "operator";

fn ca_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ))
}

/// A GitHub client that resolves every token to a single fixed operator. Used
/// to exercise the bearer-authenticated `GET /servers` endpoint offline.
#[derive(Debug)]
struct StubGitHub {
    login: String,
}

#[async_trait]
impl GitHubClient for StubGitHub {
    async fn start_device_flow(&self) -> Result<DeviceAuthorization, GitHubError> {
        unimplemented!("device flow not used in these tests")
    }
    async fn poll_device_flow(&self, _: &str) -> Result<DeviceTokenOutcome, GitHubError> {
        unimplemented!("device flow not used in these tests")
    }
    async fn get_user(&self, _: &str) -> Result<GitHubUser, GitHubError> {
        Ok(GitHubUser {
            login: self.login.clone(),
            id: 4242,
            name: None,
            email: None,
        })
    }
    async fn get_user_orgs(&self, _: &str) -> Result<Vec<String>, GitHubError> {
        Ok(Vec::new())
    }
    async fn get_user_teams(&self, _: &str) -> Result<Vec<String>, GitHubError> {
        Ok(Vec::new())
    }
}

/// App state with the test CA, a stub GitHub client, and `operator` allowlisted.
async fn state(clock: Arc<TestClock>) -> AppState {
    let options = SqliteConnectOptions::from_str(":memory:")
        .expect("opts")
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5));
    let pool: SqlitePool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("pool");
    db::migrate(&pool).await.expect("migrate");

    let mut config = Config::default();
    config.server.tls.enabled = false;
    config.access.allowed_users = vec![OPERATOR.to_string()];

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
    AppState::new(config, pool, dyn_clock)
        .with_ca(ca)
        .with_github(Arc::new(StubGitHub {
            login: OPERATOR.to_string(),
        }))
}

/// Generate an Ed25519 agent key, returning its OpenSSH public line and the
/// raw 32-byte seed used to sign requests.
fn agent_key() -> (String, [u8; 32]) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen");
    let public = key.public_key().to_openssh().expect("openssh");
    let seed = match key.key_data() {
        KeypairData::Ed25519(kp) => kp.private.to_bytes(),
        _ => panic!("expected ed25519 keypair"),
    };
    (public, seed)
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
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Enroll a machine with the given public key, returning its `machine_id`.
async fn enroll(state: &AppState, public_key: &str, hostname: &str) -> String {
    let server_identity = state
        .ca()
        .expect("ca")
        .primary_public_key()
        .expect("ca public key");
    let service = EnrollmentService::sqlite(state.db().clone(), state.clock_arc(), server_identity);
    let token = service
        .create_enrollment_token("admin", TimeDelta::hours(1), true)
        .await
        .expect("mint token")
        .plaintext;

    let request = Request::builder()
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
        .unwrap();
    let (status, body) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "enroll failed: {body}");
    body["machine_id"].as_str().expect("machine_id").to_string()
}

fn heartbeat_body() -> Value {
    json!({
        "agent_version": "0.1.0",
        "hostname": "pi-zero",
        "os": "linux",
        "kernel": "6.12",
        "ip": "192.168.1.20",
        "current_generation": 17,
        "uptime_seconds": 123456,
    })
}

/// Build a signed heartbeat request with explicit timestamp and nonce, signed
/// with `sign_with` (normally the enrolled key, but a different key for the
/// bad-signature test).
fn signed_heartbeat(
    machine_id: &str,
    timestamp: i64,
    nonce: &str,
    body: &Value,
    sign_with: &[u8; 32],
) -> Request<Body> {
    let body_str = body.to_string();
    let body_hash = signing::body_sha256_hex(body_str.as_bytes());
    let canonical = signing::canonical_string(
        machine_id,
        timestamp,
        nonce,
        "POST",
        HEARTBEAT_PATH,
        &body_hash,
    );
    let signature = signing::sign_canonical(sign_with, &canonical);
    Request::builder()
        .method("POST")
        .uri(HEARTBEAT_PATH)
        .header("content-type", "application/json")
        .header(signing::HEADER_MACHINE_ID, machine_id)
        .header(signing::HEADER_TIMESTAMP, timestamp.to_string())
        .header(signing::HEADER_NONCE, nonce)
        .header(signing::HEADER_SIGNATURE, signature)
        .body(Body::from(body_str))
        .unwrap()
}

fn servers_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/api/v1/servers")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn heartbeat_succeeds_for_signed_request() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;

    let now = clock.now().timestamp();
    let request = signed_heartbeat(&machine_id, now, "nonce-1", &heartbeat_body(), &seed);
    let (status, body) = call(state.clone(), request).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["next_heartbeat_seconds"], 60);
    assert!(body["server_time"]
        .as_str()
        .unwrap()
        .starts_with("2026-06-24"));

    // last_seen / agent fields were persisted.
    let row: (Option<String>, i64, Option<String>) = sqlx::query_as(
        "SELECT last_seen, current_generation, ip FROM machines WHERE machine_id = ?",
    )
    .bind(&machine_id)
    .fetch_one(state.db())
    .await
    .expect("row");
    assert!(row.0.is_some());
    assert_eq!(row.1, 17);
    assert_eq!(row.2.as_deref(), Some("192.168.1.20"));
}

#[tokio::test]
async fn replayed_request_is_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    let first = signed_heartbeat(&machine_id, now, "dup-nonce", &heartbeat_body(), &seed);
    let (status, _) = call(state.clone(), first).await;
    assert_eq!(status, StatusCode::OK);

    // Identical nonce within the window => replay.
    let replay = signed_heartbeat(&machine_id, now, "dup-nonce", &heartbeat_body(), &seed);
    let (status, _) = call(state.clone(), replay).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_signature_is_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, _seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    // Sign with a different key than the one enrolled.
    let (_other_public, other_seed) = agent_key();
    let request = signed_heartbeat(
        &machine_id,
        now,
        "nonce-bad",
        &heartbeat_body(),
        &other_seed,
    );
    let (status, _) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tampered_body_is_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    // Sign the canonical for the original body, then send a different body.
    let original = heartbeat_body();
    let body_str = original.to_string();
    let body_hash = signing::body_sha256_hex(body_str.as_bytes());
    let canonical = signing::canonical_string(
        &machine_id,
        now,
        "nonce-tamper",
        "POST",
        HEARTBEAT_PATH,
        &body_hash,
    );
    let signature = signing::sign_canonical(&seed, &canonical);
    let mut tampered = original.clone();
    tampered["current_generation"] = json!(9999);
    let request = Request::builder()
        .method("POST")
        .uri(HEARTBEAT_PATH)
        .header("content-type", "application/json")
        .header(signing::HEADER_MACHINE_ID, &machine_id)
        .header(signing::HEADER_TIMESTAMP, now.to_string())
        .header(signing::HEADER_NONCE, "nonce-tamper")
        .header(signing::HEADER_SIGNATURE, signature)
        .body(Body::from(tampered.to_string()))
        .unwrap();
    let (status, _) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_machine_is_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (_public, seed) = agent_key();
    let now = clock.now().timestamp();

    let request = signed_heartbeat(
        "srv_does_not_exist",
        now,
        "nonce-x",
        &heartbeat_body(),
        &seed,
    );
    let (status, _) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn old_timestamp_is_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;

    // 120s in the past — outside the ±60s window.
    let stale = clock.now().timestamp() - 120;
    let request = signed_heartbeat(&machine_id, stale, "nonce-old", &heartbeat_body(), &seed);
    let (status, _) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_signing_headers_are_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let request = Request::builder()
        .method("POST")
        .uri(HEARTBEAT_PATH)
        .header("content-type", "application/json")
        .body(Body::from(heartbeat_body().to_string()))
        .unwrap();
    let (status, _) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn server_list_requires_authorized_bearer() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;

    // No bearer at all => 401.
    let (status, _) = call(
        state.clone(),
        Request::builder()
            .method("GET")
            .uri("/api/v1/servers")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn server_list_denies_unlisted_user() {
    let clock = fixed_clock();
    // Stub resolves to a login that is NOT on the allowlist.
    let options = SqliteConnectOptions::from_str(":memory:")
        .unwrap()
        .create_if_missing(true);
    let pool: SqlitePool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let mut config = Config::default();
    config.server.tls.enabled = false;
    config.access.allowed_users = vec!["someone-else".to_string()];
    let dyn_clock: Arc<dyn Clock> = clock;
    let state = AppState::new(config, pool, dyn_clock).with_github(Arc::new(StubGitHub {
        login: OPERATOR.to_string(),
    }));

    let (status, _) = call(state, servers_request("tok")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn server_list_reflects_derived_liveness() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;

    // Heartbeat at t0 => ONLINE.
    let now = clock.now().timestamp();
    let (status, _) = call(
        state.clone(),
        signed_heartbeat(&machine_id, now, "n-live", &heartbeat_body(), &seed),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(state.clone(), servers_request("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["machine_id"], machine_id.as_str());
    assert_eq!(body[0]["status"], "ONLINE");
    assert_eq!(body[0]["ip"], "192.168.1.20");
    assert_eq!(body[0]["current_generation"], 17);

    // +3 minutes => STALE.
    clock.advance(TimeDelta::minutes(3));
    let (_, body) = call(state.clone(), servers_request("tok")).await;
    assert_eq!(body[0]["status"], "STALE");

    // +11 minutes total => OFFLINE.
    clock.advance(TimeDelta::minutes(8));
    let (_, body) = call(state.clone(), servers_request("tok")).await;
    assert_eq!(body[0]["status"], "OFFLINE");
}

#[tokio::test]
async fn enrolled_but_never_seen_machine_is_offline() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, _seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;

    let (status, body) = call(state.clone(), servers_request("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body[0]["machine_id"], machine_id.as_str());
    assert_eq!(body[0]["status"], "OFFLINE");
    assert_eq!(body[0]["last_seen"], Value::Null);
}
