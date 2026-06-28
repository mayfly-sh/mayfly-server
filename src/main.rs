//! Mayfly Server binary entry point.
//!
//! Bootstraps in fail-fast order: configuration, logging, database, shared
//! application state, then starts the HTTPS server.

use std::sync::Arc;

use anyhow::Context;
use mayfly_server::bundle::{BundleSigner, Ed25519BundleSigner};
use mayfly_server::ca::CaManager;
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
    let pool = db::connect(&config.database.url).await.with_context(|| {
        format!(
            "failed to connect to or migrate the database at '{}'",
            config.database.url
        )
    })?;
    tracing::info!(url = %config.database.url, "database connected and migrated");

    // 4. GitHub client (validated config guarantees credentials are present).
    let github = Arc::new(RealGitHubClient::from_config(&config.github));

    // 5. Certificate authority (fail-fast: loads, decrypts, and validates every
    //    stored CA, bootstrapping a first CA when storage is empty). Never logs
    //    key material or passphrases.
    let clock = Arc::new(SystemClock);
    let ca = Arc::new(
        CaManager::from_config(&config.ca, pool.clone(), clock.clone())
            .await
            .context("failed to load the certificate authority")?,
    );
    tracing::info!(
        generation = ca.generation(),
        key_count = ca.key_count(),
        active_keys = ca.active_key_count(),
        bundle_fingerprint = %ca.bundle_fingerprint(),
        "ssh certificate authority loaded",
    );

    // 6. Bundle Signing Key — a dedicated Ed25519 key (NOT an SSH CA) used only
    //    to sign the CA trust bundle. Loaded from the configured environment
    //    variable, else generated and persisted under the CA storage directory.
    //    Never logs the seed.
    let bundle_signer = Arc::new(
        Ed25519BundleSigner::load_or_create(
            &config.bundle.signing_key_env,
            std::path::Path::new(&config.ca.storage_directory),
        )
        .map_err(|err| anyhow::anyhow!("failed to load the bundle signing key: {err}"))?,
    );
    tracing::info!(
        bundle_signing_public_key = %bundle_signer.public_key_openssh(),
        "bundle signing key ready",
    );

    // 7. Shared application state with the production clock.
    let state = AppState::new(config, pool, clock)
        .with_github(github)
        .with_ca(ca)
        .with_bundle_signer(bundle_signer);

    // 8. Serve HTTPS until a shutdown signal is received.
    server::run(state).await?;

    tracing::info!("server stopped");
    Ok(())
}
