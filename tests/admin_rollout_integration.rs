//! End-to-end tests for the fleet rollout console admin API (013D).
//!
//! GitHub is mocked with wiremock; the CA manager is constructed from the
//! committed encrypted test key (generation 1). A small fleet is seeded through
//! the real registry/bundle paths, bundle audit events through the real append
//! path, then the read-only rollout endpoints are exercised through the full
//! axum router via `oneshot`.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeZone, Utc};
use mayfly_server::audit::NewAuditEntry;
use mayfly_server::bundle::Ed25519BundleSigner;
use mayfly_server::ca::CaManager;
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::{AccessConfig, Config};
use mayfly_server::db;
use mayfly_server::github::RealGitHubClient;
use mayfly_server::machines::{
    HeartbeatUpdate, MachineRepository, MachineStatus, NewMachine, SqliteMachineRepository,
};
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

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap()
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(now()))
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

fn new_machine(suffix: &str) -> NewMachine {
    NewMachine {
        machine_id: format!("srv_{suffix}"),
        hostname: format!("host-{suffix}"),
        public_key: format!("ssh-ed25519 AAAA{suffix}"),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        agent_version: "0.1.0".to_string(),
        status: MachineStatus::Active,
        enrolled_at: now(),
    }
}

/// Seed a fleet against generation 1 (the committed test CA):
///
/// - `a`: synced to gen 1, online → completed.
/// - `b`: synced to gen 0, online → lagging (generation mismatch).
/// - `c`: never synced, offline → stuck (offline).
///
/// Plus bundle audit events (applied/rollback) through the real append path.
async fn seed_fleet(state: &AppState) {
    let repo = SqliteMachineRepository;
    let mut conn = state.db().acquire().await.expect("conn");
    for s in ["a", "b", "c"] {
        repo.insert(&mut conn, &new_machine(s))
            .await
            .expect("insert");
    }
    // a and b heartbeat now → online; c never seen → offline.
    for id in ["srv_a", "srv_b"] {
        repo.update_last_seen(
            &mut conn,
            &HeartbeatUpdate {
                machine_id: id,
                now: now(),
                agent_version: "0.1.0",
                ip: Some("10.0.0.1"),
                current_generation: 1,
            },
        )
        .await
        .expect("hb");
    }
    drop(conn);

    // Apply generation 1 to `a` and an older generation 0 to `b` via the real
    // bundle-service path (sets synced_generation/last_sync).
    let bundle = state.bundle_service().expect("bundle service");
    bundle
        .record_applied("srv_a", 1, "sha256:aaaa", now())
        .await
        .expect("apply a");
    bundle
        .record_applied("srv_b", 0, "sha256:bbbb", now())
        .await
        .expect("apply b");

    // Bundle rollout audit events for timeline/history/ETA.
    let audit = state.audit();
    audit
        .append_audit_event(
            NewAuditEntry::new("bundle.applied", "agent")
                .with_subject("srv_a")
                .with_metadata(
                    json!({ "machine_id": "srv_a", "generation": 1, "fingerprint": "sha256:aaaa" }),
                ),
        )
        .await
        .expect("seed applied");
    audit
        .append_audit_event(
            NewAuditEntry::new("bundle.rollback", "agent")
                .with_subject("srv_b")
                .with_metadata(json!({ "machine_id": "srv_b", "generation": 1, "reason": "sshd reload failed" })),
        )
        .await
        .expect("seed rollback");
}

#[tokio::test]
async fn rollout_denies_unauthorized_and_audits_the_denial() {
    let server = MockServer::start().await;
    mount_user(&server, "intruder", 99).await;
    let state = state_for(&server.uri(), access_users(&[])).await;

    let (status, _) = call(&state, get("/api/v1/admin/rollout", Some("tok"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let page = state
        .audit()
        .search(&mayfly_server::audit::AuditQuery {
            event_type: Some("ops.admin_denied".to_string()),
            ..mayfly_server::audit::AuditQuery::recent()
        })
        .await
        .expect("search");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].subject.as_deref(), Some("rollout.status"));
}

#[tokio::test]
async fn rollout_status_reports_progress_and_health() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_fleet(&state).await;

    let (status, body) = call(&state, get("/api/v1/admin/rollout", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["latest_generation"], 1);
    assert_eq!(body["active_machines"], 3);
    assert_eq!(body["completed"], 1);
    assert_eq!(body["remaining"], 2);
    assert_eq!(body["percentage"], 33.3);
    assert_eq!(body["health"]["status"], "Degraded");
    // Breakdown buckets sum to active.
    let b = &body["breakdown"];
    let sum = b["healthy"].as_i64().unwrap()
        + b["stale"].as_i64().unwrap()
        + b["offline"].as_i64().unwrap()
        + b["failed"].as_i64().unwrap()
        + b["pending"].as_i64().unwrap();
    assert_eq!(sum, 3);
    assert_eq!(b["healthy"], 1);
}

#[tokio::test]
async fn rollout_generations_and_machine_filters() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_fleet(&state).await;

    let (status, body) = call(
        &state,
        get("/api/v1/admin/rollout/generations", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let gens = body["generations"].as_array().unwrap();
    assert!(gens
        .iter()
        .any(|g| g["generation"] == 1 && g["is_latest"] == true));

    // state=stuck → only the offline machine c.
    let (status, body) = call(
        &state,
        get("/api/v1/admin/rollout/machines?state=stuck", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert_eq!(body["machines"][0]["hostname"], "host-c");
    assert_eq!(body["machines"][0]["category"], "offline");

    // state=current → only a.
    let (status, body) = call(
        &state,
        get("/api/v1/admin/rollout/machines?state=current", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert_eq!(body["machines"][0]["hostname"], "host-a");

    // Bad selector → 400.
    let (status, _) = call(
        &state,
        get("/api/v1/admin/rollout/machines?state=bogus", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rollout_explain_stuck_and_health() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_fleet(&state).await;

    let (status, body) = call(&state, get("/api/v1/admin/rollout/explain", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["complete"], false);
    let cats: Vec<&str> = body["categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["category"].as_str().unwrap())
        .collect();
    assert!(cats.contains(&"offline"));
    assert!(cats.contains(&"generation_mismatch"));

    let (status, body) = call(&state, get("/api/v1/admin/rollout/stuck", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 1);
    assert!(body["stuck"][0]["recommendation"].is_string());

    let (status, body) = call(&state, get("/api/v1/admin/rollout/health", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "Degraded");
    assert!(!body["reasons"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn rollout_timeline_and_history() {
    let server = MockServer::start().await;
    mount_user(&server, "octocat", 1).await;
    let state = state_for(&server.uri(), access_users(&["octocat"])).await;
    seed_fleet(&state).await;

    let (status, body) = call(
        &state,
        get("/api/v1/admin/rollout/timeline?limit=10", Some("tok")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["count"].as_u64().unwrap() >= 2);
    let outcomes: Vec<&str> = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["outcome"].as_str().unwrap())
        .collect();
    assert!(outcomes.contains(&"applied"));
    assert!(outcomes.contains(&"rolled_back"));

    let (status, body) = call(&state, get("/api/v1/admin/rollout/history", Some("tok"))).await;
    assert_eq!(status, StatusCode::OK);
    let gen1 = body["generations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["generation"] == 1)
        .expect("generation 1 in history");
    assert!(gen1["total_applies"].as_i64().unwrap() >= 1);
    assert_eq!(gen1["is_latest"], true);
}
