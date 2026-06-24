//! HTTPS server: TLS termination, protocol negotiation, and graceful shutdown.
//!
//! A single [`TcpListener`] is fronted by a rustls [`TlsAcceptor`]. Each
//! accepted connection negotiates HTTP/2 or HTTP/1.1 via ALPN and is served by
//! the `hyper-util` automatic protocol builder. There is no plaintext listener.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::routes::build_router;
use crate::state::AppState;
use crate::tls::TlsError;
use crate::{dev_certs, tls};

/// Errors that can occur while starting or running the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The configured bind host could not be parsed as an IP address.
    #[error("invalid bind host '{0}': expected an IP address")]
    InvalidHost(String),

    /// TLS material could not be loaded, generated, or configured.
    #[error(transparent)]
    Tls(#[from] TlsError),

    /// Network / IO error binding or accepting connections.
    #[error("server io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Resolve TLS material, bind the listener, and serve until a shutdown signal.
pub async fn run(state: AppState) -> Result<(), ServerError> {
    let tls_config = resolve_tls_config(&state)?;
    let addr = socket_addr(&state)?;
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    log_startup(&state, local_addr);

    serve(state, listener, tls_config, shutdown_signal()).await
}

/// Serve connections on `listener` until `shutdown` completes.
///
/// Exposed for integration tests, which provide their own listener and
/// shutdown future.
pub async fn serve(
    state: AppState,
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServerError> {
    let acceptor = TlsAcceptor::from(tls_config);
    let router = build_router(state);
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown requested; no longer accepting connections");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to accept connection");
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let router = router.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(err) => {
                            tracing::debug!(error = %err, %peer, "TLS handshake failed");
                            return;
                        }
                    };

                    let io = TokioIo::new(tls_stream);
                    let service = TowerToHyperService::new(router);

                    if let Err(err) = ConnBuilder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        tracing::debug!(error = %err, %peer, "connection terminated with error");
                    }
                });
            }
        }
    }

    Ok(())
}

/// Determine the TLS configuration from explicit paths or a dev certificate.
fn resolve_tls_config(state: &AppState) -> Result<Arc<ServerConfig>, ServerError> {
    let tls = &state.config().server.tls;

    let (certs, key) = match (&tls.cert_path, &tls.key_path) {
        (Some(cert), Some(key)) => tls::load_pem(cert, key)?,
        _ => {
            // Validation guarantees we only reach here in development.
            let paths = dev_certs::ensure(Path::new(dev_certs::DEV_CERT_DIR))?;
            tracing::warn!(
                directory = dev_certs::DEV_CERT_DIR,
                "using a self-signed development certificate; do not use in production"
            );
            tls::load_pem(&paths.cert, &paths.key)?
        }
    };

    Ok(tls::server_config(certs, key)?)
}

/// Parse the configured host and port into a socket address.
fn socket_addr(state: &AppState) -> Result<SocketAddr, ServerError> {
    let server = &state.config().server;
    let ip: IpAddr = server
        .host
        .parse()
        .map_err(|_| ServerError::InvalidHost(server.host.clone()))?;
    Ok(SocketAddr::new(ip, server.port))
}

/// Emit the startup banner.
fn log_startup(state: &AppState, addr: SocketAddr) {
    let config = state.config();
    tracing::info!(
        version = crate::routes::health::VERSION,
        address = %format!("https://{addr}"),
        protocols = "HTTP/1.1, HTTP/2",
        tls_enabled = config.server.tls.enabled,
        mode = %config.environment,
        "Mayfly Server starting"
    );
}

/// Resolve when the process receives SIGINT (Ctrl-C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::config::Config;

    async fn test_state(host: &str) -> AppState {
        let pool = crate::db::connect(":memory:").await.expect("db");
        let mut config = Config::default();
        config.server.tls.enabled = false;
        config.server.host = host.to_string();
        AppState::new(config, pool, Arc::new(SystemClock))
    }

    #[tokio::test]
    async fn socket_addr_parses_ipv4() {
        let state = test_state("127.0.0.1").await;
        let addr = socket_addr(&state).expect("addr");
        assert!(addr.is_ipv4());
    }

    #[tokio::test]
    async fn socket_addr_rejects_non_ip_host() {
        let state = test_state("not-an-ip").await;
        let err = socket_addr(&state).expect_err("should reject");
        assert!(matches!(err, ServerError::InvalidHost(_)));
    }
}
