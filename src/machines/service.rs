//! Enrollment business logic.
//!
//! [`EnrollmentService`] owns the whole enrollment flow and keeps it out of the
//! HTTP handler: validate the token and request, run the duplicate checks,
//! consume the token, and create the machine — all inside **one SQLite
//! transaction** so the token consume and machine insert are atomic. The audit
//! event is recorded after the transaction commits.
//!
//! The service is generic over the repository traits so its logic can be
//! exercised against any backend; production wires the SQLite implementations.

use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use sqlx::SqlitePool;

use crate::audit::{AuditService, NewAuditEntry};
use crate::clock::Clock;
use crate::machines::errors::EnrollmentError;
use crate::machines::models::{
    EnrollRequest, EnrollResponse, EnrollmentToken, IssuedEnrollmentToken, MachineStatus,
    NewEnrollmentToken, NewMachine,
};
use crate::machines::repository::{
    EnrollmentTokenRepository, MachineRepository, SqliteEnrollmentTokenRepository,
    SqliteMachineRepository,
};
use crate::machines::{token, validation};

/// Default heartbeat interval handed to a freshly enrolled agent (seconds).
pub const DEFAULT_HEARTBEAT_INTERVAL: u32 = 60;

/// Default CA-sync interval handed to a freshly enrolled agent (seconds).
pub const DEFAULT_SYNC_INTERVAL: u32 = 300;

/// Audit event type recorded on a successful enrollment.
pub const EVENT_MACHINE_ENROLLED: &str = "machine.enrolled";

/// Orchestrates machine enrollment over the repository traits.
pub struct EnrollmentService<T = SqliteEnrollmentTokenRepository, M = SqliteMachineRepository> {
    pool: SqlitePool,
    tokens: T,
    machines: M,
    audit: AuditService,
    clock: Arc<dyn Clock>,
    server_identity: String,
    heartbeat_interval: u32,
    sync_interval: u32,
    bundle_signing_key: Option<String>,
}

impl EnrollmentService {
    /// Build a service backed by the SQLite repositories.
    ///
    /// `server_identity` is the server's CA public key (OpenSSH Ed25519),
    /// returned to the agent so it can pin the server it enrolled with.
    pub fn sqlite(pool: SqlitePool, clock: Arc<dyn Clock>, server_identity: String) -> Self {
        Self::new(
            pool,
            SqliteEnrollmentTokenRepository,
            SqliteMachineRepository,
            clock,
            server_identity,
            DEFAULT_HEARTBEAT_INTERVAL,
            DEFAULT_SYNC_INTERVAL,
        )
    }
}

impl<T, M> EnrollmentService<T, M>
where
    T: EnrollmentTokenRepository,
    M: MachineRepository,
{
    /// Construct a service from explicit repositories and parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: SqlitePool,
        tokens: T,
        machines: M,
        clock: Arc<dyn Clock>,
        server_identity: String,
        heartbeat_interval: u32,
        sync_interval: u32,
    ) -> Self {
        let audit = AuditService::from_pool(pool.clone(), Arc::clone(&clock));
        Self {
            pool,
            tokens,
            machines,
            audit,
            clock,
            server_identity,
            heartbeat_interval,
            sync_interval,
            bundle_signing_key: None,
        }
    }

    /// Override the suggested CA-sync interval (builder style). Production wires
    /// a per-host jittered value here.
    #[must_use]
    pub fn with_sync_interval(mut self, sync_interval: u32) -> Self {
        self.sync_interval = sync_interval;
        self
    }

    /// Set the base64 Bundle Signing Key returned to the agent for pinning
    /// (builder style).
    #[must_use]
    pub fn with_bundle_signing_key(mut self, key: Option<String>) -> Self {
        self.bundle_signing_key = key;
        self
    }

    /// Mint a new enrollment token, persist its hash, and return the one-time
    /// plaintext together with the stored record.
    ///
    /// The plaintext is generated here, hashed, and never persisted; deliver it
    /// to the operator once. `ttl` bounds the token's validity from now.
    pub async fn create_enrollment_token(
        &self,
        created_by: impl Into<String>,
        ttl: TimeDelta,
        single_use: bool,
    ) -> Result<IssuedEnrollmentToken, EnrollmentError> {
        let plaintext = token::generate_token();
        let token_hash = token::hash_token(&plaintext);
        let now = self.clock.now();
        let new = NewEnrollmentToken {
            id: uuid::Uuid::now_v7().to_string(),
            token_hash,
            created_at: now,
            expires_at: now + ttl,
            created_by: created_by.into(),
            single_use,
        };

        let mut conn = self.pool.acquire().await?;
        let record = self.tokens.create(&mut conn, &new).await?;
        Ok(IssuedEnrollmentToken { plaintext, record })
    }

    /// Enroll a machine.
    ///
    /// Validates the admission token and request, rejects duplicates, consumes
    /// the token, and creates the machine atomically. On success the audit
    /// event `machine.enrolled` is recorded and the enrollment response (with
    /// the server identity and intervals) is returned.
    pub async fn enroll(&self, request: EnrollRequest) -> Result<EnrollResponse, EnrollmentError> {
        // Cheap, allocation-free rejections first — never hash a junk token.
        if !token::is_well_formed(&request.enrollment_token) {
            return Err(EnrollmentError::TokenInvalid);
        }
        if !validation::is_valid_hostname(&request.hostname) {
            return Err(EnrollmentError::InvalidRequest(
                "invalid hostname".to_string(),
            ));
        }
        let public_key = validation::validate_ed25519_public_key(&request.public_key)
            .map_err(|_| EnrollmentError::PublicKeyInvalid)?;

        let token_hash = token::hash_token(&request.enrollment_token);
        let now = self.clock.now();

        // Single transaction: token lookup → checks → consume → insert.
        let mut tx = self.pool.begin().await?;

        let token_record = self
            .tokens
            .find_by_hash(&mut tx, &token_hash)
            .await?
            .ok_or(EnrollmentError::TokenInvalid)?;

        // Constant-time comparison of the looked-up hash against the computed
        // one (defense in depth on top of the indexed lookup).
        if !token::constant_time_eq(token_record.token_hash.as_bytes(), token_hash.as_bytes()) {
            return Err(EnrollmentError::TokenInvalid);
        }
        validate_token_state(&token_record, now)?;

        if self
            .machines
            .find_by_hostname(&mut tx, &request.hostname)
            .await?
            .is_some()
        {
            return Err(EnrollmentError::HostAlreadyEnrolled);
        }
        if self
            .machines
            .find_by_public_key(&mut tx, &public_key)
            .await?
            .is_some()
        {
            return Err(EnrollmentError::PublicKeyAlreadyExists);
        }

        // Consume atomically; a concurrent enrollment that already consumed a
        // single-use token causes this to report `false`.
        if !self
            .tokens
            .consume(&mut tx, &token_record.id, token_record.single_use, now)
            .await?
        {
            return Err(EnrollmentError::TokenAlreadyUsed);
        }

        let new_machine = NewMachine {
            machine_id: generate_machine_id(),
            hostname: request.hostname.clone(),
            public_key: public_key.clone(),
            os: request.os.clone(),
            arch: request.arch.clone(),
            agent_version: request.agent_version.clone(),
            status: MachineStatus::Active,
            enrolled_at: now,
        };
        let machine = self
            .machines
            .insert(&mut tx, &new_machine)
            .await
            .map_err(map_insert_error)?;

        tx.commit().await?;

        // Audit after the enrollment is durable. The fingerprint is recorded
        // (not the key body) and the token is never referenced.
        let fingerprint = validation::public_key_fingerprint(&public_key)
            .unwrap_or_else(|| "unknown".to_string());
        self.audit
            .append_audit_event(
                NewAuditEntry::new(EVENT_MACHINE_ENROLLED, "system")
                    .with_subject(machine.machine_id.clone())
                    .with_metadata(json!({
                        "hostname": machine.hostname,
                        "agent_version": machine.agent_version,
                        "public_key_fingerprint": fingerprint,
                    })),
            )
            .await
            .map_err(EnrollmentError::from_audit)?;

        Ok(EnrollResponse {
            machine_id: machine.machine_id,
            heartbeat_interval: self.heartbeat_interval,
            sync_interval: self.sync_interval,
            server_identity: self.server_identity.clone(),
            bundle_signing_key: self.bundle_signing_key.clone(),
        })
    }
}

/// Check a token's expiry and single-use state at `now`.
fn validate_token_state(
    token: &EnrollmentToken,
    now: DateTime<Utc>,
) -> Result<(), EnrollmentError> {
    if token.expires_at <= now {
        return Err(EnrollmentError::TokenExpired);
    }
    if token.single_use && token.used_at.is_some() {
        return Err(EnrollmentError::TokenAlreadyUsed);
    }
    Ok(())
}

/// Generate a fresh server-issued machine identifier (`srv_<uuid>`).
fn generate_machine_id() -> String {
    format!("srv_{}", uuid::Uuid::now_v7().simple())
}

/// Translate a unique-constraint violation on insert into the matching
/// duplicate error, so a race between the pre-check and the insert still
/// returns the correct client error rather than a generic 500.
fn map_insert_error(err: sqlx::Error) -> EnrollmentError {
    if let sqlx::Error::Database(db) = &err {
        let message = db.message();
        if message.contains("machines.hostname") {
            return EnrollmentError::HostAlreadyEnrolled;
        }
        if message.contains("machines.public_key") {
            return EnrollmentError::PublicKeyAlreadyExists;
        }
    }
    EnrollmentError::Internal(anyhow::Error::new(err))
}

impl EnrollmentError {
    /// Map an audit failure to an internal error (cause logged, not returned).
    fn from_audit(err: crate::errors::AuditError) -> Self {
        EnrollmentError::Internal(anyhow::Error::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::db;
    use crate::machines::token;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    const FIXED_NOW: &str = "2026-06-24T12:00:00Z";

    fn server_identity() -> String {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("gen")
            .public_key()
            .to_openssh()
            .expect("openssh")
    }

    fn agent_public_key() -> String {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("gen")
            .public_key()
            .to_openssh()
            .expect("openssh")
    }

    async fn service() -> (EnrollmentService, Arc<TestClock>) {
        let pool = db::connect(":memory:").await.expect("connect");
        let clock = Arc::new(TestClock::at_rfc3339(FIXED_NOW).expect("clock"));
        let svc = EnrollmentService::sqlite(pool, clock.clone(), server_identity());
        (svc, clock)
    }

    /// Mint a token and return its plaintext.
    async fn mint_token(svc: &EnrollmentService, single_use: bool) -> String {
        svc.create_enrollment_token("admin", TimeDelta::hours(1), single_use)
            .await
            .expect("mint")
            .plaintext
    }

    fn request(token: &str, hostname: &str, public_key: &str) -> EnrollRequest {
        EnrollRequest {
            enrollment_token: token.to_string(),
            hostname: hostname.to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            agent_version: "0.1.0".to_string(),
            public_key: public_key.to_string(),
        }
    }

    #[tokio::test]
    async fn valid_enrollment_succeeds() {
        let (svc, _clock) = service().await;
        let tok = mint_token(&svc, true).await;
        let response = svc
            .enroll(request(&tok, "web-01", &agent_public_key()))
            .await
            .expect("enroll");

        assert!(response.machine_id.starts_with("srv_"));
        assert_eq!(response.heartbeat_interval, DEFAULT_HEARTBEAT_INTERVAL);
        assert_eq!(response.sync_interval, DEFAULT_SYNC_INTERVAL);
        assert!(response.server_identity.starts_with("ssh-ed25519 "));
    }

    #[tokio::test]
    async fn token_is_consumed_after_enrollment() {
        let (svc, _clock) = service().await;
        let plaintext = mint_token(&svc, true).await;
        svc.enroll(request(&plaintext, "web-01", &agent_public_key()))
            .await
            .expect("enroll");

        // The same token cannot be used again.
        let err = svc
            .enroll(request(&plaintext, "web-02", &agent_public_key()))
            .await
            .expect_err("reuse rejected");
        assert!(matches!(err, EnrollmentError::TokenAlreadyUsed));

        // And the stored record now has used_at set.
        let mut conn = svc.pool.acquire().await.expect("conn");
        let hash = token::hash_token(&plaintext);
        let record = svc
            .tokens
            .find_by_hash(&mut conn, &hash)
            .await
            .expect("find")
            .expect("present");
        assert!(record.used_at.is_some());
    }

    #[tokio::test]
    async fn invalid_token_is_rejected() {
        let (svc, _clock) = service().await;
        // Well-formed but never issued.
        let err = svc
            .enroll(request(
                "mf_enroll_doesnotexist",
                "web-01",
                &agent_public_key(),
            ))
            .await
            .expect_err("invalid");
        assert!(matches!(err, EnrollmentError::TokenInvalid));

        // Malformed format is rejected without touching the database.
        let err = svc
            .enroll(request("not-a-token", "web-01", &agent_public_key()))
            .await
            .expect_err("malformed");
        assert!(matches!(err, EnrollmentError::TokenInvalid));
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (svc, clock) = service().await;
        let tok = mint_token(&svc, true).await;
        // Advance beyond the one-hour TTL.
        clock.advance(TimeDelta::hours(2));
        let err = svc
            .enroll(request(&tok, "web-01", &agent_public_key()))
            .await
            .expect_err("expired");
        assert!(matches!(err, EnrollmentError::TokenExpired));
    }

    #[tokio::test]
    async fn already_used_token_is_rejected() {
        let (svc, _clock) = service().await;
        let tok = mint_token(&svc, true).await;
        svc.enroll(request(&tok, "web-01", &agent_public_key()))
            .await
            .expect("first");
        let err = svc
            .enroll(request(&tok, "web-02", &agent_public_key()))
            .await
            .expect_err("used");
        assert!(matches!(err, EnrollmentError::TokenAlreadyUsed));
    }

    #[tokio::test]
    async fn duplicate_hostname_is_rejected() {
        let (svc, _clock) = service().await;
        let tok1 = mint_token(&svc, true).await;
        let tok2 = mint_token(&svc, true).await;
        svc.enroll(request(&tok1, "web-01", &agent_public_key()))
            .await
            .expect("first");
        let err = svc
            .enroll(request(&tok2, "web-01", &agent_public_key()))
            .await
            .expect_err("dup host");
        assert!(matches!(err, EnrollmentError::HostAlreadyEnrolled));
    }

    #[tokio::test]
    async fn duplicate_public_key_is_rejected() {
        let (svc, _clock) = service().await;
        let tok1 = mint_token(&svc, true).await;
        let tok2 = mint_token(&svc, true).await;
        let key = agent_public_key();
        svc.enroll(request(&tok1, "web-01", &key))
            .await
            .expect("first");
        let err = svc
            .enroll(request(&tok2, "web-02", &key))
            .await
            .expect_err("dup key");
        assert!(matches!(err, EnrollmentError::PublicKeyAlreadyExists));
    }

    #[tokio::test]
    async fn invalid_public_key_is_rejected() {
        let (svc, _clock) = service().await;
        let tok = mint_token(&svc, true).await;
        let err = svc
            .enroll(request(&tok, "web-01", "not a key"))
            .await
            .expect_err("bad key");
        assert!(matches!(err, EnrollmentError::PublicKeyInvalid));
    }

    #[tokio::test]
    async fn invalid_hostname_is_rejected() {
        let (svc, _clock) = service().await;
        let tok = mint_token(&svc, true).await;
        let err = svc
            .enroll(request(&tok, "bad host!", &agent_public_key()))
            .await
            .expect_err("bad host");
        assert!(matches!(err, EnrollmentError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn enrollment_writes_audit_event() {
        let (svc, _clock) = service().await;
        let tok = mint_token(&svc, true).await;
        let response = svc
            .enroll(request(&tok, "web-01", &agent_public_key()))
            .await
            .expect("enroll");

        let row: (String, String, Option<String>, String) = sqlx::query_as(
            "SELECT event_type, actor, subject, metadata FROM audit_log \
             ORDER BY chain_position DESC LIMIT 1",
        )
        .fetch_one(&svc.pool)
        .await
        .expect("audit row");
        assert_eq!(row.0, EVENT_MACHINE_ENROLLED);
        assert_eq!(row.1, "system");
        assert_eq!(row.2.as_deref(), Some(response.machine_id.as_str()));
        // Metadata carries the fingerprint, never the token or raw key body.
        assert!(row.3.contains("public_key_fingerprint"));
        assert!(row.3.contains("web-01"));
        assert!(!row.3.contains("mf_enroll_"));
    }

    #[tokio::test]
    async fn failed_enrollment_rolls_back_token_consume() {
        // Pre-enroll a machine, then attempt to reuse its public key with a
        // fresh token. The duplicate check fails *before* the consume, so the
        // second token must remain unused (transaction integrity).
        let (svc, _clock) = service().await;
        let key = agent_public_key();
        let tok1 = mint_token(&svc, true).await;
        svc.enroll(request(&tok1, "web-01", &key))
            .await
            .expect("first");

        let tok2 = mint_token(&svc, true).await;
        let err = svc
            .enroll(request(&tok2, "web-02", &key))
            .await
            .expect_err("dup key");
        assert!(matches!(err, EnrollmentError::PublicKeyAlreadyExists));

        // tok2 was never consumed.
        let mut conn = svc.pool.acquire().await.expect("conn");
        let record = svc
            .tokens
            .find_by_hash(&mut conn, &token::hash_token(&tok2))
            .await
            .expect("find")
            .expect("present");
        assert!(
            record.used_at.is_none(),
            "token must not be consumed on failure"
        );

        // And web-02 was never created.
        assert!(svc
            .machines
            .find_by_hostname(&mut conn, "web-02")
            .await
            .expect("q")
            .is_none());
    }

    #[tokio::test]
    async fn machine_ids_are_unique() {
        let (svc, _clock) = service().await;
        let tok1 = mint_token(&svc, true).await;
        let tok2 = mint_token(&svc, true).await;
        let a = svc
            .enroll(request(&tok1, "web-01", &agent_public_key()))
            .await
            .expect("first");
        let b = svc
            .enroll(request(&tok2, "web-02", &agent_public_key()))
            .await
            .expect("second");
        assert_ne!(a.machine_id, b.machine_id);
    }
}
