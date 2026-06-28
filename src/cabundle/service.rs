//! CA bundle business logic: assemble and fingerprint the current bundle,
//! seed the server's own CA key, and record agent acknowledgements.
//!
//! There is **no route logic here** — handlers in [`crate::routes::ca_bundle`]
//! deal with HTTP concerns (the `If-Generation` header, `304 Not Modified`,
//! status codes); this service only owns data and validation.

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use crate::cabundle::models::{
    AckError, AckRequest, AckResponse, CaBundle, CaBundleError, CaBundleKey, MAX_FINGERPRINT_LEN,
};
use crate::cabundle::repository::{CaKeyRepository, SqliteCaKeyRepository};

/// Assembles the current CA bundle and records acknowledgements over a
/// [`CaKeyRepository`].
#[derive(Clone)]
pub struct CaBundleService<R: CaKeyRepository> {
    pool: SqlitePool,
    keys: R,
}

impl CaBundleService<SqliteCaKeyRepository> {
    /// Build the production service backed by SQLite.
    pub fn sqlite(pool: SqlitePool) -> Self {
        Self {
            pool,
            keys: SqliteCaKeyRepository,
        }
    }
}

impl<R: CaKeyRepository> CaBundleService<R> {
    /// Construct with an explicit repository (for tests).
    pub fn new(pool: SqlitePool, keys: R) -> Self {
        Self { pool, keys }
    }

    /// Seed the server's own CA key into an empty bundle (idempotent).
    pub async fn ensure_seeded(
        &self,
        key_id: &str,
        public_key: &str,
        now: DateTime<Utc>,
    ) -> Result<(), CaBundleError> {
        let mut conn = self.pool.acquire().await?;
        self.keys
            .ensure_seeded(&mut conn, key_id, public_key, now)
            .await?;
        Ok(())
    }

    /// The current generation only (cheap; used for `If-Generation` handling).
    pub async fn current_generation(&self) -> Result<i64, CaBundleError> {
        let mut conn = self.pool.acquire().await?;
        Ok(self.keys.current_generation(&mut conn).await?)
    }

    /// Assemble, validate, and fingerprint the current bundle.
    pub async fn current_bundle(&self) -> Result<CaBundle, CaBundleError> {
        let mut conn = self.pool.acquire().await?;
        let generation = self.keys.current_generation(&mut conn).await?;
        let records = self.keys.list_enabled(&mut conn).await?;
        let keys: Vec<CaBundleKey> = records
            .into_iter()
            .map(|r| CaBundleKey {
                key_id: r.key_id,
                public_key: r.public_key,
            })
            .collect();
        CaBundle::build(generation, keys)
    }

    /// Record a machine's acknowledgement after verifying it matches the
    /// current bundle.
    pub async fn record_ack(
        &self,
        machine_id: &str,
        ack: &AckRequest,
        now: DateTime<Utc>,
    ) -> Result<AckResponse, AckError> {
        if ack.status.trim() != "success" {
            return Err(AckError::Invalid("status must be 'success'".to_string()));
        }
        let fingerprint = ack.fingerprint.trim();
        if fingerprint.is_empty() || fingerprint.len() > MAX_FINGERPRINT_LEN {
            return Err(AckError::Invalid("fingerprint is invalid".to_string()));
        }

        // The acknowledgement must match the bundle we are currently serving.
        let bundle = self.current_bundle().await?;
        if ack.generation != bundle.generation || fingerprint != bundle.fingerprint {
            return Err(AckError::Mismatch);
        }

        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| AckError::Bundle(CaBundleError::Database(e)))?;
        let updated = self
            .keys
            .record_ack(&mut conn, machine_id, bundle.generation, &bundle.fingerprint, now)
            .await
            .map_err(|e| AckError::Bundle(CaBundleError::Database(e)))?;
        if !updated {
            return Err(AckError::UnknownMachine);
        }

        Ok(AckResponse {
            status: "recorded",
            generation: bundle.generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
    use std::str::FromStr;

    fn at(seconds: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, seconds).unwrap()
    }

    fn openssh_public(seed: u8) -> String {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let verifying = signing.verifying_key();
        let key_data = ssh_key::public::Ed25519PublicKey(verifying.to_bytes());
        ssh_key::PublicKey::from(ssh_key::public::KeyData::Ed25519(key_data))
            .to_openssh()
            .expect("openssh")
    }

    /// A single-connection in-memory pool so all service calls share one DB.
    async fn service() -> CaBundleService<SqliteCaKeyRepository> {
        let options = SqliteConnectOptions::from_str(":memory:")
            .expect("opts")
            .create_if_missing(true);
        let pool: SqlitePool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("pool");
        db::migrate(&pool).await.expect("migrate");
        CaBundleService::sqlite(pool)
    }

    #[tokio::test]
    async fn current_bundle_after_seed_has_one_key() {
        let svc = service().await;
        svc.ensure_seeded("mayfly-ca", &openssh_public(1), at(0))
            .await
            .unwrap();
        let bundle = svc.current_bundle().await.unwrap();
        assert_eq!(bundle.generation, 1);
        assert_eq!(bundle.keys.len(), 1);
        assert!(bundle.fingerprint.starts_with("sha256:"));
    }

    #[tokio::test]
    async fn current_bundle_without_seed_is_empty_error() {
        let svc = service().await;
        assert!(matches!(
            svc.current_bundle().await.unwrap_err(),
            // generation 0 trips the generation check first.
            CaBundleError::InvalidGeneration
        ));
    }

    #[tokio::test]
    async fn ack_rejects_non_success_status() {
        let svc = service().await;
        svc.ensure_seeded("mayfly-ca", &openssh_public(1), at(0))
            .await
            .unwrap();
        let ack = AckRequest {
            generation: 1,
            fingerprint: "sha256:x".to_string(),
            status: "failure".to_string(),
        };
        assert!(matches!(
            svc.record_ack("srv_1", &ack, at(1)).await.unwrap_err(),
            AckError::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn ack_rejects_mismatched_generation() {
        let svc = service().await;
        svc.ensure_seeded("mayfly-ca", &openssh_public(1), at(0))
            .await
            .unwrap();
        let bundle = svc.current_bundle().await.unwrap();
        let ack = AckRequest {
            generation: 99,
            fingerprint: bundle.fingerprint.clone(),
            status: "success".to_string(),
        };
        assert!(matches!(
            svc.record_ack("srv_1", &ack, at(1)).await.unwrap_err(),
            AckError::Mismatch
        ));
    }

    #[tokio::test]
    async fn ack_unknown_machine_is_reported() {
        let svc = service().await;
        svc.ensure_seeded("mayfly-ca", &openssh_public(1), at(0))
            .await
            .unwrap();
        let bundle = svc.current_bundle().await.unwrap();
        let ack = AckRequest {
            generation: bundle.generation,
            fingerprint: bundle.fingerprint.clone(),
            status: "success".to_string(),
        };
        assert!(matches!(
            svc.record_ack("srv_missing", &ack, at(1)).await.unwrap_err(),
            AckError::UnknownMachine
        ));
    }
}
