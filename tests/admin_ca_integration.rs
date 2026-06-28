//! End-to-end tests for the CA management admin API.
//!
//! GitHub is mocked with wiremock; the CA manager is constructed from the
//! committed encrypted test key (storage passphrase = the test passphrase), so
//! `generate`/`import`/`enable`/`disable`/`rename` exercise the real lifecycle
//! through the full axum router driven via `oneshot`.

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
use ssh_key::{Algorithm, LineEnding, PrivateKey};
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

fn get(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::empty()).unwrap()
}

fn patch(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
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
async fn generate_lists_gets_and_patches_a_ca() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 1).await;
    let state = state_for(&server.uri(), access_users(&["vasugarg"])).await;

    // Generate a new CA.
    let (status, body) = call(
        &state,
        post(
            "/api/v1/admin/ca/generate",
            Some("gho_token"),
            json!({ "key_id": "ca-2026-q3", "passphrase": CA_PASSPHRASE }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["key_id"], "ca-2026-q3");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["issued_certificates"], 0);
    assert!(body["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert!(body.get("public_key").is_some());
    // The private key is never exposed.
    assert!(body.get("private_key").is_none());
    let id = body["id"].as_str().unwrap().to_string();

    // List shows both the bootstrap-equivalent key and the new one.
    let (status, body) = call(&state, get("/api/v1/admin/ca", Some("gho_token"))).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["key_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["ca-2026-q3", "mayfly-ca"]);

    // Get the specific CA by id.
    let (status, body) = call(
        &state,
        get(&format!("/api/v1/admin/ca/{id}"), Some("gho_token")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], id);

    // Disable it, then rename it, via PATCH.
    let (status, body) = call(
        &state,
        patch(
            &format!("/api/v1/admin/ca/{id}"),
            "gho_token",
            json!({ "enabled": false }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], false);

    let (status, body) = call(
        &state,
        patch(
            &format!("/api/v1/admin/ca/{id}"),
            "gho_token",
            json!({ "key_id": "ca-archived" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key_id"], "ca-archived");

    // The lifecycle was audited.
    let events = audit_events(&state).await;
    assert!(events.contains(&"ca.generated".to_string()));
    assert!(events.contains(&"ca.disabled".to_string()));
    assert!(events.contains(&"ca.renamed".to_string()));
}

#[tokio::test]
async fn import_adds_an_existing_key() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 1).await;
    let state = state_for(&server.uri(), access_users(&["vasugarg"])).await;

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen");
    let armored = key
        .encrypt(&mut OsRng, "import-pass")
        .expect("encrypt")
        .to_openssh(LineEnding::LF)
        .expect("encode")
        .to_string();

    let (status, body) = call(
        &state,
        post(
            "/api/v1/admin/ca/import",
            Some("gho_token"),
            json!({ "key_id": "ca-imported", "private_key": armored, "passphrase": "import-pass" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["key_id"], "ca-imported");

    // Importing the same material again is a conflict.
    let (status, _) = call(
        &state,
        post(
            "/api/v1/admin/ca/import",
            Some("gho_token"),
            json!({ "key_id": "ca-dup", "private_key": armored, "passphrase": "import-pass" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn generate_with_wrong_passphrase_is_bad_request() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 1).await;
    let state = state_for(&server.uri(), access_users(&["vasugarg"])).await;

    let (status, _) = call(
        &state,
        post(
            "/api/v1/admin/ca/generate",
            Some("gho_token"),
            json!({ "key_id": "ca-x", "passphrase": "not-the-storage-passphrase" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unauthorized_caller_is_forbidden() {
    let server = MockServer::start().await;
    // The token resolves to a user that is NOT on the allowlist.
    mount_user(&server, "intruder", 99).await;
    let state = state_for(&server.uri(), access_users(&["vasugarg"])).await;

    let (status, _) = call(
        &state,
        post(
            "/api/v1/admin/ca/generate",
            Some("gho_token"),
            json!({ "key_id": "ca-x", "passphrase": CA_PASSPHRASE }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The denial was audited.
    assert!(audit_events(&state)
        .await
        .contains(&"ca.admin_denied".to_string()));
}

#[tokio::test]
async fn missing_bearer_token_is_unauthorized() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 1).await;
    let state = state_for(&server.uri(), access_users(&["vasugarg"])).await;

    let (status, _) = call(&state, get("/api/v1/admin/ca", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_ca_id_is_not_found() {
    let server = MockServer::start().await;
    mount_user(&server, "vasugarg", 1).await;
    let state = state_for(&server.uri(), access_users(&["vasugarg"])).await;

    let (status, _) = call(
        &state,
        get("/api/v1/admin/ca/does-not-exist", Some("gho_token")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
