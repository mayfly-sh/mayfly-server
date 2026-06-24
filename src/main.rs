//! Mayfly Server binary entry point.
//!
//! Bootstraps in fail-fast order: configuration, logging, database, shared
//! application state, then starts the HTTPS server.

use std::sync::Arc;

use anyhow::Context;
use mayfly_server::ca::CaService;
use mayfly_server::clock::SystemClock;
use mayfly_server::config::Config;
use mayfly_server::github::RealGitHubClient;
use mayfly_server::state::AppState;
use mayfly_server::{db, logging, server};

/// Default configuration file path; overridable via `MAYFLY_CONFIG`.
const DEFAULT_CONFIG_PATH: &str = "config.yaml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // An explicitly provided path must exist; the default path is optional.
    let (config_path, required) = match std::env::var("MAYFLY_CONFIG") {
        Ok(path) if !path.trim().is_empty() => (path, true),
        _ => (DEFAULT_CONFIG_PATH.to_string(), false),
    };

    // 1. Configuration (fail-fast, validated).
    let config = Config::load(&config_path, required)?;

    // 2. Logging (must come before anything we want to observe).
    logging::init(&config.logging)?;
    tracing::info!(
        config_path = %config_path,
        host = %config.server.host,
        port = config.server.port,
        "configuration loaded",
    );

    // 3. Database + migrations.
    let pool = db::connect(&config.database.url)
        .await
        .with_context(|| {
            format!(
                "failed to connect to or migrate the database at '{}'",
                config.database.url
            )
        })?;
    tracing::info!(url = %config.database.url, "database connected and migrated");

    // 4. GitHub client (validated config guarantees credentials are present).
    let github = Arc::new(RealGitHubClient::from_config(&config.github));

    // 5. Certificate authority (fail-fast: loads and decrypts the CA key now).
    let clock = Arc::new(SystemClock);
    let ca = Arc::new(CaService::from_config(&config.ca, clock.clone())?);
    tracing::info!(
        key_id = %config.ca.key_id,
        ca_public_key = %ca.get_ca_public_key()?,
        "ssh certificate authority loaded",
    );

    // 6. Shared application state with the production clock.
    let state = AppState::new(config, pool, clock)
        .with_github(github)
        .with_ca(ca);

    // 7. Serve HTTPS until a shutdown signal is received.
    server::run(state).await?;

    tracing::info!("server stopped");
    Ok(())
}
