//! End-to-end tests for the machine administration admin API (013A):
//! list/detail, the approve/disable/enable/revoke lifecycle, delete, and
//! re-enroll/rotate-identity — plus the security-critical proof that a
//! disabled/revoked/deleted machine's signed requests are rejected at the
//! agent-auth chokepoint, and that every mutation is audited while reads are not.
//!
//! GitHub is stubbed to resolve every bearer to a single allowlisted operator;
//! agents are enrolled and sign heartbeats exactly as in production using the
//! server's own `agentauth::signing` helpers.

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
const TOKEN: &str = "gho_operator";

fn ca_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ))
}

#[derive(Debug)]
struct StubGitHub {
    login: String,
}

#[async_trait]
impl GitHubClient for StubGitHub {
    async fn start_device_flow(&self) -> Result<DeviceAuthorization, GitHubError> {
        unimplemented!()
    }
    async fn poll_device_flow(&self, _: &str) -> Result<DeviceTokenOutcome, GitHubError> {
        unimplemented!()
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

async fn state_with_operator(operator_login: &str, allowed: &[&str]) -> (AppState, Arc<TestClock>) {
    let clock = fixed_clock();
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
    config.access.allowed_users = allowed.iter().map(|s| s.to_string()).collect();

    let dyn_clock: Arc<dyn Clock> = clock.clone();
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
    let state = AppState::new(config, pool, dyn_clock)
        .with_ca(ca)
        .with_github(Arc::new(StubGitHub {
            login: operator_login.to_string(),
        }));
    (state, clock)
}

async fn state() -> (AppState, Arc<TestClock>) {
    state_with_operator(OPERATOR, &[OPERATOR]).await
}

fn agent_key() -> (String, [u8; 32]) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen");
    let public = key.public_key().to_openssh().expect("openssh");
    let seed = match key.key_data() {
        KeypairData::Ed25519(kp) => kp.private.to_bytes(),
        _ => panic!("expected ed25519"),
    };
    (public, seed)
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn admin_get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

fn admin_post(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn admin_delete(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn enroll(state: &AppState, public_key: &str, hostname: &str) -> String {
    let server_identity = state.ca().unwrap().primary_public_key().unwrap();
    let service = EnrollmentService::sqlite(state.db().clone(), state.clock_arc(), server_identity);
    let token = service
        .create_enrollment_token("admin", TimeDelta::hours(1), true)
        .await
        .expect("mint")
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
    let (status, body) = call(state, request).await;
    assert_eq!(status, StatusCode::OK, "enroll failed: {body}");
    body["machine_id"].as_str().unwrap().to_string()
}

fn signed_heartbeat(machine_id: &str, ts: i64, nonce: &str, seed: &[u8; 32]) -> Request<Body> {
    let body = json!({
        "agent_version": "0.1.0", "hostname": "h", "os": "linux", "kernel": "6.12",
        "ip": "10.0.0.9", "current_generation": 3, "uptime_seconds": 1,
    });
    let body_str = body.to_string();
    let body_hash = signing::body_sha256_hex(body_str.as_bytes());
    let canonical =
        signing::canonical_string(machine_id, ts, nonce, "POST", HEARTBEAT_PATH, &body_hash);
    let signature = signing::sign_canonical(seed, &canonical);
    Request::builder()
        .method("POST")
        .uri(HEARTBEAT_PATH)
        .header("content-type", "application/json")
        .header(signing::HEADER_MACHINE_ID, machine_id)
        .header(signing::HEADER_TIMESTAMP, ts.to_string())
        .header(signing::HEADER_NONCE, nonce)
        .header(signing::HEADER_SIGNATURE, signature)
        .body(Body::from(body_str))
        .unwrap()
}

async fn audit_events(state: &AppState) -> Vec<String> {
    sqlx::query_as::<_, (String,)>("SELECT event_type FROM audit_log ORDER BY chain_position ASC")
        .fetch_all(state.db())
        .await
        .expect("audit query")
        .into_iter()
        .map(|r| r.0)
        .collect()
}

#[tokio::test]
async fn list_and_get_require_authorization() {
    let (state, _clock) = state().await;
    let (public, _seed) = agent_key();
    let id = enroll(&state, &public, "web-01").await;

    // No bearer => 401.
    let (status, _) = call(&state, admin_get("/api/v1/admin/machines", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Authorized list shows the enrolled machine with a derived view.
    let (status, body) = call(&state, admin_get("/api/v1/admin/machines", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["machine_id"], id.as_str());
    assert_eq!(arr[0]["hostname"], "web-01");
    assert_eq!(arr[0]["status"], "active");
    assert_eq!(arr[0]["liveness"], "OFFLINE");
    assert!(arr[0]["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    // latest_generation is present (a CA is configured) and machine is behind.
    assert_eq!(arr[0]["up_to_date"], false);

    // Detail by id.
    let (status, body) = call(
        &state,
        admin_get(&format!("/api/v1/admin/machines/{id}"), Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["machine_id"], id.as_str());

    // Reads are NOT audited (only enrollment so far).
    assert_eq!(
        audit_events(&state).await,
        vec!["machine.enrolled".to_string()]
    );
}

#[tokio::test]
async fn unauthorized_operator_is_forbidden_and_audited() {
    // The token resolves to a user NOT on the allowlist.
    let (state, _clock) = state_with_operator("intruder", &[OPERATOR]).await;
    let (status, _) = call(&state, admin_get("/api/v1/admin/machines", Some(TOKEN))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(audit_events(&state)
        .await
        .contains(&"machine.admin_denied".to_string()));
}

#[tokio::test]
async fn disable_blocks_heartbeat_and_enable_restores_it() {
    let (state, clock) = state().await;
    let (public, seed) = agent_key();
    let id = enroll(&state, &public, "web-01").await;
    let now = clock.now().timestamp();

    // Healthy heartbeat first.
    let (status, _) = call(&state, signed_heartbeat(&id, now, "n1", &seed)).await;
    assert_eq!(status, StatusCode::OK);

    // Disable via admin API.
    let (status, body) = call(
        &state,
        admin_post(&format!("/api/v1/admin/machines/{id}/disable"), TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "disabled");

    // The disabled machine's signed heartbeat is now rejected at the chokepoint.
    let (status, _) = call(&state, signed_heartbeat(&id, now, "n2", &seed)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Enable again restores it.
    let (status, body) = call(
        &state,
        admin_post(&format!("/api/v1/admin/machines/{id}/enable"), TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "active");
    let (status, _) = call(&state, signed_heartbeat(&id, now, "n3", &seed)).await;
    assert_eq!(status, StatusCode::OK);

    let events = audit_events(&state).await;
    assert!(events.contains(&"machine.disabled".to_string()));
    assert!(events.contains(&"machine.enabled".to_string()));
}

#[tokio::test]
async fn revoke_blocks_heartbeat_and_is_audited() {
    let (state, clock) = state().await;
    let (public, seed) = agent_key();
    let id = enroll(&state, &public, "web-01").await;
    let now = clock.now().timestamp();

    let (status, body) = call(
        &state,
        admin_post(&format!("/api/v1/admin/machines/{id}/revoke"), TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "revoked");

    let (status, _) = call(&state, signed_heartbeat(&id, now, "n", &seed)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(audit_events(&state)
        .await
        .contains(&"machine.revoked".to_string()));
}

#[tokio::test]
async fn delete_removes_machine_and_blocks_it() {
    let (state, clock) = state().await;
    let (public, seed) = agent_key();
    let id = enroll(&state, &public, "web-01").await;
    let now = clock.now().timestamp();

    let (status, body) = call(
        &state,
        admin_delete(&format!("/api/v1/admin/machines/{id}"), TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);
    assert_eq!(body["hostname"], "web-01");

    // Gone: detail is 404; heartbeat from an unknown machine is rejected.
    let (status, _) = call(
        &state,
        admin_get(&format!("/api/v1/admin/machines/{id}"), Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&state, signed_heartbeat(&id, now, "n", &seed)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(audit_events(&state)
        .await
        .contains(&"machine.deleted".to_string()));
}

#[tokio::test]
async fn reenroll_deletes_old_and_mints_token_for_new_identity() {
    let (state, _clock) = state().await;
    let (public, _seed) = agent_key();
    let id = enroll(&state, &public, "web-01").await;

    let (status, body) = call(
        &state,
        admin_post(&format!("/api/v1/admin/machines/{id}/reenroll"), TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token = body["token"].as_str().expect("token");
    assert!(token.starts_with("mf_enroll_"));

    // Old machine is gone; the freed hostname can be re-enrolled with a NEW key.
    let (status, _) = call(
        &state,
        admin_get(&format!("/api/v1/admin/machines/{id}"), Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (new_public, _new_seed) = agent_key();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/machines/enroll")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "enrollment_token": token,
                "hostname": "web-01",
                "os": "linux", "arch": "x86_64", "agent_version": "0.1.0",
                "public_key": new_public,
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = call(&state, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(audit_events(&state)
        .await
        .contains(&"machine.reenroll_requested".to_string()));
}

#[tokio::test]
async fn rotate_identity_is_audited_distinctly() {
    let (state, _clock) = state().await;
    let (public, _seed) = agent_key();
    let id = enroll(&state, &public, "web-01").await;

    let (status, _) = call(
        &state,
        admin_post(
            &format!("/api/v1/admin/machines/{id}/rotate-identity"),
            TOKEN,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(audit_events(&state)
        .await
        .contains(&"machine.identity_rotation_requested".to_string()));
}

#[tokio::test]
async fn list_filters_by_status() {
    let (state, _clock) = state().await;
    let (p1, _s1) = agent_key();
    let (p2, _s2) = agent_key();
    let id1 = enroll(&state, &p1, "web-01").await;
    let _id2 = enroll(&state, &p2, "web-02").await;

    // Revoke one.
    call(
        &state,
        admin_post(&format!("/api/v1/admin/machines/{id1}/revoke"), TOKEN),
    )
    .await;

    let (status, body) = call(
        &state,
        admin_get("/api/v1/admin/machines?status=active", Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let hosts: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["hostname"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, vec!["web-02"]);

    let (_status, body) = call(
        &state,
        admin_get("/api/v1/admin/machines?status=revoked", Some(TOKEN)),
    )
    .await;
    assert_eq!(body.as_array().unwrap().len(), 1);

    // An unknown status is a 400.
    let (status, _) = call(
        &state,
        admin_get("/api/v1/admin/machines?status=bogus", Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_unknown_machine_is_not_found() {
    let (state, _clock) = state().await;
    let (status, _) = call(
        &state,
        admin_get("/api/v1/admin/machines/srv_missing", Some(TOKEN)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
