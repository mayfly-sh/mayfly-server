//! Integration tests for the HTTPS server and its endpoints.
//!
//! Two layers:
//! 1. Router-level tests via `oneshot` (no TLS) — fast and deterministic.
//! 2. A real end-to-end TLS test over a loopback socket using a rustls client
//!    that trusts the generated development certificate.
//!
//! All networking is loopback only; no external network access is used.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::Config;
use mayfly_server::routes::build_router;
use mayfly_server::state::AppState;
use mayfly_server::{dev_certs, server, tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

async fn test_state() -> AppState {
    let pool = mayfly_server::db::connect(":memory:").await.expect("db");
    let mut config = Config::default();
    config.server.tls.enabled = false;
    let clock = Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap());
    AppState::new(config, pool, clock as Arc<dyn Clock>)
}

#[tokio::test]
async fn health_endpoint_returns_ok_json() {
    let app = build_router(test_state().await);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert!(json["uptime_seconds"].is_u64());
}

#[tokio::test]
async fn ready_endpoint_returns_ready_json() {
    let app = build_router(test_state().await);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(json["status"], "ready");
    assert_eq!(json["checks"]["config"], "ok");
}

#[tokio::test]
async fn includes_request_id_header() {
    let app = build_router(test_state().await);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert!(response.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn end_to_end_https_health_over_tls() {
    // Generate a development certificate in an isolated temp directory.
    let dir = std::env::temp_dir().join(format!("mayfly-e2e-{}", uuid::Uuid::now_v7()));
    let paths = dev_certs::ensure(&dir).expect("dev certs");
    let (certs, key) = tls::load_pem(&paths.cert, &paths.key).expect("load pem");
    let tls_config = tls::server_config(certs.clone(), key).expect("server config");

    // Bind an ephemeral loopback port and start serving.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let local_addr = listener.local_addr().expect("addr");

    let state = test_state().await;
    let server = tokio::spawn(async move {
        let _ = server::serve(state, listener, tls_config, std::future::pending()).await;
    });

    // Build a rustls client that trusts the generated certificate.
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).expect("add root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(local_addr).await.expect("connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    let request = "GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");

    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        tls_stream.read_to_end(&mut response),
    )
    .await
    .expect("read did not time out")
    .expect("read response");

    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("200 OK"), "status line missing: {text}");
    assert!(text.contains("\"status\":\"ok\""), "body missing: {text}");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
