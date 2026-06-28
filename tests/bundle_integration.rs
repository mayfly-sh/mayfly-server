//! End-to-end tests for the signed CA bundle distribution protocol:
//! `GET /api/v1/agent/ca-bundle` (signed bundle + ETag/304), the ack endpoint
//! with apply/rollback/signature_failed outcomes, the admin fleet-status view,
//! and CA retirement safety (blocked / forced / safe).
//!
//! Agent requests are signed exactly as a real agent would, using the server's
//! own `agentauth::signing` helpers. The Bundle Signing Key and the polling
//! jitter RNG are injected deterministically so signatures and intervals are
//! reproducible without sleeping.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{TimeDelta, TimeZone, Utc};
use mayfly_server::agentauth::signing;
use mayfly_server::bundle::{
    verify_signed_bundle, BundleSigner, Ed25519BundleSigner, SignedBundle,
};
use mayfly_server::ca::{CaManager, RandomSource};
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
use std::path::PathBuf;
use tower::ServiceExt;

const CA_PASSPHRASE: &str = "mayfly-test-passphrase";
const OPERATOR: &str = "operator";
const BUNDLE_PATH: &str = "/api/v1/agent/ca-bundle";
const ACK_PATH: &str = "/api/v1/agent/ca-bundle/ack";
const SIGNING_SEED: [u8; 32] = [42u8; 32];

fn ca_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ))
}

/// Resolves every token to a single fixed operator (allowlisted).
#[derive(Debug)]
struct StubGitHub;

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
            login: OPERATOR.to_string(),
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

/// Deterministic jitter RNG that always returns the midpoint, so the jittered
/// sync interval equals the configured base (keeps assertions stable).
#[derive(Debug)]
struct MidpointJitter;
impl RandomSource for MidpointJitter {
    fn next_index(&self, bound: usize) -> usize {
        bound / 2
    }
}

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
        .with_github(Arc::new(StubGitHub))
        .with_bundle_signer(Arc::new(Ed25519BundleSigner::from_seed(&SIGNING_SEED)))
        .with_jitter(Arc::new(MidpointJitter))
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

async fn call(state: AppState, request: Request<Body>) -> (StatusCode, Vec<u8>, Option<String>) {
    let response = build_router(state)
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let etag = response
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, bytes, etag)
}

fn json_body(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

async fn enroll(state: &AppState, public_key: &str, hostname: &str) -> String {
    let server_identity = state.ca().expect("ca").primary_public_key().expect("pk");
    let service = EnrollmentService::sqlite(state.db().clone(), state.clock_arc(), server_identity);
    let token = service
        .create_enrollment_token("admin", TimeDelta::hours(1), true)
        .await
        .expect("token")
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
    let (status, body, _) = call(state.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "enroll: {}", json_body(&body));
    json_body(&body)["machine_id"]
        .as_str()
        .expect("machine_id")
        .to_string()
}

/// Build a signed agent request for `method`/`path` with the given body bytes.
#[allow(clippy::too_many_arguments)]
fn signed(
    method: &str,
    path: &str,
    body: &[u8],
    machine_id: &str,
    nonce: &str,
    timestamp: i64,
    seed: &[u8; 32],
    extra: &[(&str, &str)],
) -> Request<Body> {
    let body_hash = signing::body_sha256_hex(body);
    let canonical =
        signing::canonical_string(machine_id, timestamp, nonce, method, path, &body_hash);
    let signature = signing::sign_canonical(seed, &canonical);
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header(signing::HEADER_MACHINE_ID, machine_id)
        .header(signing::HEADER_TIMESTAMP, timestamp.to_string())
        .header(signing::HEADER_NONCE, nonce)
        .header(signing::HEADER_SIGNATURE, signature);
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    builder.body(Body::from(body.to_vec())).unwrap()
}

fn bearer(method: &str, path: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer tok")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn signed_get_returns_signed_bundle_that_verifies() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    let req = signed("GET", BUNDLE_PATH, b"", &machine_id, "n1", now, &seed, &[]);
    let (status, body, etag) = call(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK);

    let bundle: SignedBundle = serde_json::from_slice(&body).expect("signed bundle");
    assert_eq!(bundle.bundle_version, 1);
    assert_eq!(bundle.generation, 1);
    assert_eq!(bundle.signature_algorithm, "ssh-ed25519");
    assert_eq!(bundle.keys.len(), 1);

    // ETag is the quoted fingerprint.
    assert_eq!(
        etag.as_deref(),
        Some(format!("\"{}\"", bundle.fingerprint).as_str())
    );

    // Verifies against the pinned signing key.
    let pinned = Ed25519BundleSigner::from_seed(&SIGNING_SEED);
    verify_signed_bundle(&bundle, &pinned.public_key_bytes(), clock.now()).expect("verify");
    assert_eq!(
        bundle.bundle_signing_public_key,
        pinned.public_key_openssh()
    );
}

#[tokio::test]
async fn etag_304_when_if_none_match_matches() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    // First fetch to learn the ETag.
    let (status, _, etag) = call(
        state.clone(),
        signed("GET", BUNDLE_PATH, b"", &machine_id, "n1", now, &seed, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let etag = etag.expect("etag");

    // Conditional re-fetch with matching validator => 304, no body.
    let (status, body, etag2) = call(
        state.clone(),
        signed(
            "GET",
            BUNDLE_PATH,
            b"",
            &machine_id,
            "n2",
            now,
            &seed,
            &[("if-none-match", &etag)],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(etag2.as_deref(), Some(etag.as_str()));
}

#[tokio::test]
async fn etag_mismatch_returns_full_bundle() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    let (status, body, _) = call(
        state.clone(),
        signed(
            "GET",
            BUNDLE_PATH,
            b"",
            &machine_id,
            "n1",
            now,
            &seed,
            &[("if-none-match", "\"sha256:stale\"")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.is_empty());
}

#[tokio::test]
async fn unsigned_bundle_request_is_rejected() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let req = Request::builder()
        .method("GET")
        .uri(BUNDLE_PATH)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = call(state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ack_applied_updates_synced_generation_and_audits() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    let fingerprint = state.ca().unwrap().bundle_fingerprint();
    let ack = json!({ "generation": 1, "fingerprint": fingerprint, "status": "applied" });
    let body = ack.to_string();
    let req = signed(
        "POST",
        ACK_PATH,
        body.as_bytes(),
        &machine_id,
        "a1",
        now,
        &seed,
        &[],
    );
    let (status, resp, _) = call(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "{}", json_body(&resp));
    assert_eq!(json_body(&resp)["status"], "recorded");

    // synced state persisted.
    let row: (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT synced_generation, bundle_fingerprint FROM machines WHERE machine_id = ?",
    )
    .bind(&machine_id)
    .fetch_one(state.db())
    .await
    .expect("row");
    assert_eq!(row.0, Some(1));
    assert_eq!(row.1.as_deref(), Some(fingerprint.as_str()));

    // Audit event recorded.
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE event_type = 'bundle.applied'")
            .fetch_one(state.db())
            .await
            .expect("count");
    assert_eq!(count.0, 1);
}

#[tokio::test]
async fn ack_rollback_is_audited_without_advancing_sync() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    let ack = json!({
        "generation": 1,
        "fingerprint": state.ca().unwrap().bundle_fingerprint(),
        "status": "rollback",
        "reason": "sshd reload failed"
    });
    let body = ack.to_string();
    let req = signed(
        "POST",
        ACK_PATH,
        body.as_bytes(),
        &machine_id,
        "r1",
        now,
        &seed,
        &[],
    );
    let (status, _, _) = call(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK);

    // synced_generation must NOT have advanced.
    let row: (Option<i64>,) =
        sqlx::query_as("SELECT synced_generation FROM machines WHERE machine_id = ?")
            .bind(&machine_id)
            .fetch_one(state.db())
            .await
            .expect("row");
    assert_eq!(row.0, None);

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE event_type = 'bundle.rollback'")
            .fetch_one(state.db())
            .await
            .expect("count");
    assert_eq!(count.0, 1);
}

#[tokio::test]
async fn ack_unknown_status_is_bad_request() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    let ack = json!({ "generation": 1, "fingerprint": "sha256:x", "status": "bogus" });
    let body = ack.to_string();
    let req = signed(
        "POST",
        ACK_PATH,
        body.as_bytes(),
        &machine_id,
        "b1",
        now,
        &seed,
        &[],
    );
    let (status, _, _) = call(state.clone(), req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bundle_status_reports_fleet_rollout() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    // Heartbeat to become ONLINE.
    let hb = json!({
        "agent_version": "0.1.0", "hostname": "pi-zero", "os": "linux",
        "kernel": "6.12", "ip": "10.0.0.5", "current_generation": 1, "uptime_seconds": 10
    });
    let hb_body = hb.to_string();
    let (status, _, _) = call(
        state.clone(),
        signed(
            "POST",
            "/api/v1/agent/heartbeat",
            hb_body.as_bytes(),
            &machine_id,
            "h1",
            now,
            &seed,
            &[],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Ack generation 1 so it counts toward rollout.
    let ack = json!({ "generation": 1, "fingerprint": state.ca().unwrap().bundle_fingerprint(), "status": "applied" });
    let ack_body = ack.to_string();
    call(
        state.clone(),
        signed(
            "POST",
            ACK_PATH,
            ack_body.as_bytes(),
            &machine_id,
            "k1",
            now,
            &seed,
            &[],
        ),
    )
    .await;

    let (status, body, _) = call(
        state.clone(),
        bearer("GET", "/api/v1/admin/bundle/status", Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v = json_body(&body);
    assert_eq!(v["total_machines"], 1);
    assert_eq!(v["online"], 1);
    assert_eq!(v["latest_generation"], 1);
    assert_eq!(v["rollout_percentage"], 100.0);
    assert_eq!(v["oldest_generation"], 1);
    assert_eq!(v["generations"][0]["generation"], 1);
    assert_eq!(v["generations"][0]["count"], 1);
}

/// Cross-protocol: the full server↔agent wire flow in one test.
///
/// Server generates a signed bundle → it is verified exactly as the agent would
/// (pinned OpenSSH signing key, JSON canonical bytes, `verify_strict`) → an ACK
/// is serialized in the agent's exact `AckReport` wire shape
/// (`{"generation","fingerprint","status"}`) → the server accepts it without
/// aliases → the applied generation is recorded → fleet rollout metrics update.
#[tokio::test]
async fn cross_protocol_bundle_verify_ack_record_and_metrics() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let (public, seed) = agent_key();
    let machine_id = enroll(&state, &public, "pi-zero").await;
    let now = clock.now().timestamp();

    // 1) Server generates the signed bundle.
    let req = signed("GET", BUNDLE_PATH, b"", &machine_id, "g1", now, &seed, &[]);
    let (status, body, _) = call(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK);
    let bundle: SignedBundle = serde_json::from_slice(&body).expect("signed bundle");

    // Wire shape the agent expects (C2/C3/C4/C5).
    assert_eq!(bundle.bundle_version, 1);
    assert_eq!(bundle.signature_algorithm, "ssh-ed25519");
    assert!(bundle.bundle_signing_public_key.starts_with("ssh-ed25519 "));

    // 2) Agent-equivalent verification against the pinned signing key.
    let pinned = Ed25519BundleSigner::from_seed(&SIGNING_SEED);
    verify_signed_bundle(&bundle, &pinned.public_key_bytes(), clock.now()).expect("verify");

    // Heartbeat so the machine is ONLINE and counts toward rollout.
    let hb = json!({
        "agent_version": "0.1.0", "hostname": "pi-zero", "os": "linux",
        "kernel": "6.12", "ip": "10.0.0.5", "current_generation": bundle.generation, "uptime_seconds": 10
    });
    let hb_body = hb.to_string();
    let (status, _, _) = call(
        state.clone(),
        signed(
            "POST",
            "/api/v1/agent/heartbeat",
            hb_body.as_bytes(),
            &machine_id,
            "h1",
            now,
            &seed,
            &[],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 3) ACK serialized exactly as the agent's `AckReport` does on success.
    let ack_body = format!(
        "{{\"generation\":{},\"fingerprint\":\"{}\",\"status\":\"applied\"}}",
        bundle.generation, bundle.fingerprint
    );
    let req = signed(
        "POST",
        ACK_PATH,
        ack_body.as_bytes(),
        &machine_id,
        "a1",
        now,
        &seed,
        &[],
    );
    // 4) Server accepts it without aliases.
    let (status, resp, _) = call(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "{}", json_body(&resp));
    assert_eq!(json_body(&resp)["status"], "recorded");

    // 5) Generation recorded.
    let row: (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT synced_generation, bundle_fingerprint FROM machines WHERE machine_id = ?",
    )
    .bind(&machine_id)
    .fetch_one(state.db())
    .await
    .expect("row");
    assert_eq!(row.0, Some(i64::from(bundle.generation)));
    assert_eq!(row.1.as_deref(), Some(bundle.fingerprint.as_str()));

    // 6) Fleet metrics reflect the rollout.
    let (status, body, _) = call(
        state.clone(),
        bearer("GET", "/api/v1/admin/bundle/status", Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v = json_body(&body);
    assert_eq!(v["total_machines"], 1);
    assert_eq!(v["online"], 1);
    assert_eq!(v["latest_generation"], bundle.generation);
    assert_eq!(v["rollout_percentage"], 100.0);
}

#[tokio::test]
async fn retirement_blocked_then_forced() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let ca = state.ca().expect("ca");

    // Add and then disable a second CA so it becomes a retirement candidate.
    let second = ca.generate("ca-02", CA_PASSPHRASE).await.expect("generate");
    ca.disable(&second.id).await.expect("disable");

    // An enrolled machine that never synced is treated as a dependant => unsafe.
    let (public, _seed) = agent_key();
    enroll(&state, &public, "pi-zero").await;

    // Assessment says unsafe.
    let (status, body, _) = call(
        state.clone(),
        bearer(
            "GET",
            &format!("/api/v1/admin/ca/{}/retirement", second.id),
            Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["safe"], false);
    assert_eq!(json_body(&body)["affected_machines"], 1);

    // Retire without force => 409 + denial audit.
    let (status, _, _) = call(
        state.clone(),
        bearer(
            "POST",
            &format!("/api/v1/admin/ca/{}/retire", second.id),
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let denied: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE event_type = 'ca.retirement.denied'")
            .fetch_one(state.db())
            .await
            .expect("count");
    assert_eq!(denied.0, 1);

    // Key is still managed.
    assert!(ca.get(&second.id).is_some());

    // Force => 200, forced + retired audits, and the key is gone.
    let (status, _, _) = call(
        state.clone(),
        bearer(
            "POST",
            &format!("/api/v1/admin/ca/{}/retire", second.id),
            json!({ "force": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ca.get(&second.id).is_none());

    for event in ["ca.retirement.forced", "ca.retired"] {
        let c: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE event_type = ?")
            .bind(event)
            .fetch_one(state.db())
            .await
            .expect("count");
        assert_eq!(c.0, 1, "missing {event}");
    }
}

#[tokio::test]
async fn safe_retirement_succeeds_without_force() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let ca = state.ca().expect("ca");

    // Disabled CA, and no machines depend on it (empty fleet) => safe.
    let second = ca.generate("ca-02", CA_PASSPHRASE).await.expect("generate");
    ca.disable(&second.id).await.expect("disable");

    let (status, body, _) = call(
        state.clone(),
        bearer(
            "GET",
            &format!("/api/v1/admin/ca/{}/retirement", second.id),
            Value::Null,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["safe"], true);

    let (status, _, _) = call(
        state.clone(),
        bearer(
            "POST",
            &format!("/api/v1/admin/ca/{}/retire", second.id),
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ca.get(&second.id).is_none());
}

#[tokio::test]
async fn retiring_enabled_ca_is_conflict() {
    let clock = fixed_clock();
    let state = state(clock.clone()).await;
    let ca = state.ca().expect("ca");
    let second = ca.generate("ca-02", CA_PASSPHRASE).await.expect("generate");

    // Enabled CA: assessment unsafe; force still refused by the manager.
    let (status, _, _) = call(
        state.clone(),
        bearer(
            "POST",
            &format!("/api/v1/admin/ca/{}/retire", second.id),
            json!({ "force": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(ca.get(&second.id).is_some());
}
