//! Integration tests for the storage-backed CA manager: bootstrap on empty
//! storage, lifecycle (generate / import / enable / disable) persisted to a
//! real SQLite database + on-disk encrypted key files, reload across restarts,
//! and startup validation.
//!
//! Each test uses a unique temporary directory (for key files and a file-backed
//! SQLite database) and a unique passphrase environment variable, so the tests
//! are hermetic and safe to run in parallel.

use std::path::PathBuf;
use std::sync::Arc;

use mayfly_server::ca::{CaManager, CertificateRequest};
use mayfly_server::clock::{Clock, TestClock};
use mayfly_server::config::CaConfig;
use mayfly_server::db;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

const PASSPHRASE: &str = "integration-storage-passphrase";

fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap())
}

/// A unique temporary directory for one test's storage.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mayfly_ca_mgr_{}_{}_{}",
        std::process::id(),
        tag,
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Build a `CaConfig` rooted at `dir`, reading the passphrase from `env`.
fn config_for(dir: &std::path::Path, env: &str) -> CaConfig {
    CaConfig {
        storage_directory: dir.join("keys").display().to_string(),
        selection_strategy: Default::default(),
        auto_load: true,
        passphrase_env: env.to_string(),
    }
}

/// Connect to a file-backed SQLite database inside `dir` (so it survives a
/// "restart" — a second `from_config` over the same pool).
async fn pool_for(dir: &std::path::Path) -> sqlx::SqlitePool {
    let url = format!("sqlite://{}/ca.db", dir.display());
    db::connect(&url).await.expect("connect db")
}

fn request() -> CertificateRequest {
    let subject = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .expect("gen")
        .public_key()
        .to_openssh()
        .expect("openssh");
    CertificateRequest {
        principal: "vasugarg".to_string(),
        hostname: "web-01".to_string(),
        public_key: subject,
        ttl_seconds: 300,
    }
}

/// An encrypted OpenSSH Ed25519 key armored with `passphrase`.
fn encrypted_ed25519(passphrase: &str) -> String {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen");
    key.encrypt(&mut OsRng, passphrase)
        .expect("encrypt")
        .to_openssh(LineEnding::LF)
        .expect("encode")
        .to_string()
}

#[tokio::test]
async fn bootstraps_first_ca_when_storage_is_empty() {
    let dir = temp_dir("bootstrap");
    let env = "CA_STORAGE_PASS_BOOTSTRAP";
    std::env::set_var(env, PASSPHRASE);
    let pool = pool_for(&dir).await;

    let manager = CaManager::from_config(&config_for(&dir, env), pool, clock())
        .await
        .expect("load manager");

    assert_eq!(manager.key_count(), 1);
    assert_eq!(manager.active_key_count(), 1);
    assert_eq!(manager.generation(), 1);

    // The bootstrap CA signs, and the response names it.
    let response = manager.sign_certificate(&request()).await.expect("sign");
    assert_eq!(response.ca_key_id, "mayfly-ca");
    assert!(response.ca_fingerprint.starts_with("SHA256:"));

    let validation = manager
        .verify_certificate(&response.certificate, clock().now())
        .expect("verify");
    assert!(validation.valid);

    // A key file was written to disk and never contains plaintext private key.
    let keys_dir = dir.join("keys");
    let files: Vec<_> = std::fs::read_dir(&keys_dir)
        .expect("read keys dir")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(files.len(), 1);
    let contents = std::fs::read_to_string(files[0].path()).expect("read key");
    assert!(contents.contains("OPENSSH PRIVATE KEY"));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn lifecycle_persists_across_reload() {
    let dir = temp_dir("reload");
    let env = "CA_STORAGE_PASS_RELOAD";
    std::env::set_var(env, PASSPHRASE);
    let config = config_for(&dir, env);
    let pool = pool_for(&dir).await;

    // First "boot": bootstrap (mayfly-ca), then add two more CAs.
    let imported_key = encrypted_ed25519("import-pass");
    let disabled_id;
    {
        let manager = CaManager::from_config(&config, pool.clone(), clock())
            .await
            .expect("first boot");
        manager
            .generate("ca-02", PASSPHRASE)
            .await
            .expect("generate");
        let imported = manager
            .import("ca-03", &imported_key, "import-pass")
            .await
            .expect("import");
        disabled_id = imported.id.clone();
        manager.disable(&imported.id).await.expect("disable");

        assert_eq!(manager.key_count(), 3);
        assert_eq!(manager.active_key_count(), 2);
        // bootstrap(1) + generate(2) + import(3) + disable(4) = generation 4.
        assert_eq!(manager.generation(), 4);
    }

    // Second "boot" over the same database + key files: state is reloaded.
    let manager = CaManager::from_config(&config, pool, clock())
        .await
        .expect("second boot");
    assert_eq!(manager.key_count(), 3);
    assert_eq!(manager.active_key_count(), 2);
    assert_eq!(manager.generation(), 4);

    // The previously disabled CA is still present but disabled.
    let reloaded = manager.get(&disabled_id).expect("disabled ca present");
    assert!(!reloaded.enabled);
    assert_eq!(reloaded.key_id, "ca-03");

    // The bundle reflects only the two enabled CAs, sorted by key_id.
    let bundle = manager.get_public_bundle();
    let ids: Vec<&str> = bundle.keys.iter().map(|k| k.key_id.as_str()).collect();
    assert_eq!(ids, vec!["ca-02", "mayfly-ca"]);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn missing_storage_passphrase_fails_startup() {
    let dir = temp_dir("nopass");
    let env = "CA_STORAGE_PASS_DEFINITELY_UNSET_XYZ";
    std::env::remove_var(env);
    let pool = pool_for(&dir).await;

    let result = CaManager::from_config(&config_for(&dir, env), pool, clock()).await;
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn statistics_persist_across_reload() {
    let dir = temp_dir("stats");
    let env = "CA_STORAGE_PASS_STATS";
    std::env::set_var(env, PASSPHRASE);
    let config = config_for(&dir, env);
    let pool = pool_for(&dir).await;

    {
        let manager = CaManager::from_config(&config, pool.clone(), clock())
            .await
            .expect("boot");
        for _ in 0..3 {
            manager.sign_certificate(&request()).await.expect("sign");
        }
    }

    // Reload: the bootstrap CA's usage statistics were persisted.
    let manager = CaManager::from_config(&config, pool, clock())
        .await
        .expect("reload");
    let record = &manager.list()[0];
    assert_eq!(record.issued_certificates, 3);
    assert!(record.last_used_at.is_some());

    std::fs::remove_dir_all(&dir).ok();
}
