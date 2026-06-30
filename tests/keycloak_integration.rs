//! End-to-end tests proving Keycloak is a first-class provider for the same
//! HTTP surface GitHub uses: a wiremock OIDC IdP (discovery + JWKS) issues
//! RS256 access tokens, and the full axum router resolves identity, authorizes
//! (group/role), and issues a certificate — selected purely by `provider`.
//!
//! These complement the provider-level unit tests in
//! `src/auth/keycloak/mod.rs` by exercising the wiring through
//! `resolve_identity` → `AuthzService` → CA signing → audit.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::{TimeZone, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mayfly_server::auth::{AuthenticationProvider, KeycloakProvider, KeycloakProviderConfig};
use mayfly_server::ca::CaManager;
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::{AccessConfig, Config};
use mayfly_server::db;
use mayfly_server::github::RealGitHubClient;
use mayfly_server::routes::build_router;
use mayfly_server::state::AppState;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use ssh_key::rand_core::OsRng as SshOsRng;
use ssh_key::{Algorithm as SshAlgorithm, PrivateKey};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CA_PASSPHRASE: &str = "mayfly-test-passphrase";

fn ca_key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
}

fn user_public_key() -> String {
    PrivateKey::random(&mut SshOsRng, SshAlgorithm::Ed25519)
        .expect("gen")
        .public_key()
        .to_openssh()
        .expect("openssh")
}

/// A minimal in-test OIDC identity provider: RSA signing key, JWKS, discovery
/// document, and an RS256 token minter (mirrors the unit-test helper).
struct TestIdp {
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
    issuer: String,
}

impl TestIdp {
    fn new(issuer: &str, kid: &str) -> Self {
        let mut rng = rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).expect("pem");
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");

        let pubkey = key.to_public_key();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
        let jwk = json!({
            "kty": "RSA", "use": "sig", "kid": kid, "alg": "RS256", "n": n, "e": e,
        });
        Self {
            kid: kid.to_string(),
            encoding,
            jwk,
            issuer: issuer.to_string(),
        }
    }

    fn jwks(&self) -> Value {
        json!({ "keys": [ self.jwk.clone() ] })
    }

    fn discovery(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "token_endpoint": format!("{}/protocol/openid-connect/token", self.issuer),
            "device_authorization_endpoint": format!("{}/protocol/openid-connect/auth/device", self.issuer),
            "jwks_uri": format!("{}/protocol/openid-connect/certs", self.issuer),
        })
    }

    fn mint(&self, mut claims: Value) -> String {
        let obj = claims.as_object_mut().expect("claims object");
        obj.entry("iss").or_insert(json!(self.issuer));
        let now = Utc::now().timestamp();
        obj.entry("iat").or_insert(json!(now));
        obj.entry("exp").or_insert(json!(now + 300));
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, &claims, &self.encoding).expect("encode token")
    }
}

async fn idp_server() -> (MockServer, TestIdp) {
    let server = MockServer::start().await;
    let idp = TestIdp::new(&server.uri(), "k1");
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(idp.discovery()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/protocol/openid-connect/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(idp.jwks()))
        .mount(&server)
        .await;
    (server, idp)
}

fn fixed_clock() -> Arc<TestClock> {
    Arc::new(TestClock::new(
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap(),
    ))
}

/// Build app state with a registered Keycloak provider whose issuer is `issuer`,
/// `keycloak` as the default provider, and the given access policy.
async fn state_for_keycloak(issuer: &str, clock: Arc<TestClock>, access: AccessConfig) -> AppState {
    let pool = db::connect(":memory:").await.expect("db");
    let mut config = Config::default();
    config.server.tls.enabled = false;
    config.access = access;
    config.default_provider = Some("keycloak".to_string());

    // GitHub is registered but unused here (requests select provider=keycloak).
    let github = Arc::new(RealGitHubClient::new(
        "client-id".into(),
        "client-secret".into(),
        "read:user".into(),
        "http://127.0.0.1:1/unused".into(),
        "http://127.0.0.1:1/unused".into(),
    ));

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

    let keycloak: Arc<dyn AuthenticationProvider> =
        Arc::new(KeycloakProvider::new(KeycloakProviderConfig {
            issuer_url: issuer.to_string(),
            client_id: "mayfly-cli".into(),
            client_secret: None,
            scopes: "openid profile email".into(),
            audience: None,
            clock_skew_secs: 60,
        }));

    AppState::new(config, pool, dyn_clock)
        .with_github(github)
        .with_ca(ca)
        .with_provider(keycloak)
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

fn issue_request(token: &str, public_key: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/issue")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            json!({
                "public_key": public_key,
                "hostname": "web-01",
                "ttl_seconds": 300,
                "provider": "keycloak",
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn certificate_issuance_authorized_by_group() {
    let (server, idp) = idp_server().await;
    let token = idp.mint(json!({
        "sub": "kc-sub-1",
        "preferred_username": "vasu",
        "email": "vasu@example.com",
        "groups": ["/engineering"],
    }));
    let access = AccessConfig {
        allowed_groups: vec!["engineering".into()],
        ..Default::default()
    };
    let state = state_for_keycloak(&server.uri(), fixed_clock(), access).await;
    let audit_state = state.clone();

    let (status, body) = call(state, issue_request(&token, &user_public_key())).await;
    assert_eq!(status, StatusCode::OK);
    // Principal originates from the Keycloak identity's preferred_username.
    assert_eq!(body["principal"], "vasu");
    assert_eq!(body["ca_key_id"], "mayfly-ca");

    // Audit records the issuance attributed to the Keycloak subject's username.
    let events = audit_events(&audit_state).await;
    assert_eq!(
        events,
        vec![("certificate.issued".to_string(), "vasu".to_string())]
    );
}

#[tokio::test]
async fn certificate_issuance_authorized_by_client_role() {
    let (server, idp) = idp_server().await;
    let token = idp.mint(json!({
        "sub": "kc-sub-2",
        "preferred_username": "operator",
        "resource_access": { "mayfly": { "roles": ["operator"] } },
    }));
    let access = AccessConfig {
        allowed_roles: vec!["mayfly/operator".into()],
        ..Default::default()
    };
    let state = state_for_keycloak(&server.uri(), fixed_clock(), access).await;

    let (status, body) = call(state, issue_request(&token, &user_public_key())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["principal"], "operator");
}

#[tokio::test]
async fn certificate_issuance_denied_when_not_in_allowlist() {
    let (server, idp) = idp_server().await;
    let token = idp.mint(json!({
        "sub": "kc-sub-3",
        "preferred_username": "stranger",
        "groups": ["/contractors"],
    }));
    // Empty allowlist denies everyone (deny-by-default).
    let state = state_for_keycloak(&server.uri(), fixed_clock(), AccessConfig::default()).await;
    let audit_state = state.clone();

    let (status, body) = call(state, issue_request(&token, &user_public_key())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["message"], "access denied");

    let events = audit_events(&audit_state).await;
    assert_eq!(
        events,
        vec![("certificate.denied".to_string(), "stranger".to_string())]
    );
}

#[tokio::test]
async fn expired_keycloak_token_is_unauthorized() {
    let (server, idp) = idp_server().await;
    let now = Utc::now().timestamp();
    let token = idp.mint(json!({
        "sub": "kc-sub-4",
        "preferred_username": "vasu",
        "iat": now - 1000,
        "exp": now - 600,
    }));
    let access = AccessConfig {
        allowed_users: vec!["vasu".into()],
        ..Default::default()
    };
    let state = state_for_keycloak(&server.uri(), fixed_clock(), access).await;

    let (status, _) = call(state, issue_request(&token, &user_public_key())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn whoami_resolves_keycloak_identity() {
    let (server, idp) = idp_server().await;
    let token = idp.mint(json!({
        "sub": "kc-sub-5",
        "preferred_username": "vasu",
        "email": "vasu@example.com",
        "name": "Vasu Garg",
    }));
    let state = state_for_keycloak(&server.uri(), fixed_clock(), AccessConfig::default()).await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/whoami?provider=keycloak")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["provider"], "keycloak");
    assert_eq!(body["username"], "vasu");
    assert_eq!(body["subject"], "kc-sub-5");
    assert_eq!(body["email"], "vasu@example.com");
    // Legacy GitHub fields remain present and backward-compatible.
    assert_eq!(body["github_login"], "vasu");
    assert_eq!(body["github_id"], 0);
}
