//! Mayfly Server binary entry point.
//!
//! Bootstraps the foundation in fail-fast order: configuration, logging,
//! database, and shared application state. The HTTP/TLS listener is wired in a
//! subsequent milestone.

use std::sync::Arc;

use mayfly_server::clock::SystemClock;
use mayfly_server::config::Config;
use mayfly_server::state::AppState;
use mayfly_server::{db, logging};

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
    let pool = db::connect(&config.database.url).await?;
    tracing::info!(url = %config.database.url, "database connected and migrated");

    // 4. Shared application state with the production clock.
    let clock = Arc::new(SystemClock);
    let state = AppState::new(config, pool, clock);

    tracing::info!(
        started_at = %state.started_at(),
        "foundation initialized; HTTP/TLS listener not yet implemented",
    );

    Ok(())
}
