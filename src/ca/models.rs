//! Certificate issuance types, CA records/metadata, the public bundle, and the
//! signing-key selection strategy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Minimum accepted certificate TTL, in seconds.
pub const MIN_TTL_SECONDS: u32 = 60;
/// Maximum accepted certificate TTL, in seconds.
pub const MAX_TTL_SECONDS: u32 = 3600;
/// Default TTL applied when a request specifies `ttl_seconds == 0`.
pub const DEFAULT_TTL_SECONDS: u32 = 300;

/// Maximum number of CA keys the manager will hold. Loading or adding beyond
/// this fails closed.
pub const MAX_CA_KEYS: usize = 64;

/// Maximum accepted `key_id` length.
pub const MAX_KEY_ID_LEN: usize = 64;

/// Default `key_id` for the CA generated automatically on first startup when
/// storage is empty.
pub const BOOTSTRAP_KEY_ID: &str = "mayfly-ca";

/// Strategy for choosing which enabled CA signs a given certificate.
///
/// Kept as an enum (rather than a boolean or hard-coded behaviour) so future
/// versions can add `Weighted`, `RoundRobin`, `LeastUsed`, etc. without
/// changing the public signing API. Only [`SelectionStrategy::Random`] is
/// implemented today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionStrategy {
    /// Uniformly choose one enabled key using a cryptographically secure RNG.
    #[default]
    Random,
}

/// Full, non-secret metadata for one managed CA.
///
/// This is the database row, the admin-API response body, and the in-memory
/// record the manager keeps alongside each signer. It never contains private
/// key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaRecord {
    /// Stable, server-assigned unique identifier (UUIDv7).
    pub id: String,
    /// Operator-assigned identifier, embedded as the certificate `key_id`.
    pub key_id: String,
    /// The CA's public key in OpenSSH format.
    pub public_key: String,
    /// SHA-256 fingerprint of the public key (`SHA256:...`).
    pub fingerprint: String,
    /// Whether this CA participates in signing and the public bundle.
    pub enabled: bool,
    /// When the CA was created/added.
    pub created_at: DateTime<Utc>,
    /// When the CA was most recently enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_at: Option<DateTime<Utc>>,
    /// When the CA was most recently disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<DateTime<Utc>>,
    /// When the CA most recently signed a certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Number of certificates this CA has signed.
    pub issued_certificates: u64,
    /// The bundle generation at which this CA was disabled, i.e. the first
    /// generation whose bundle no longer contains it. `None` while enabled.
    /// Used to assess retirement safety.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_generation: Option<u32>,
}

/// One enabled CA public key as published in the [`PublicBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaPublicKeyEntry {
    /// Operator-assigned key identifier.
    pub key_id: String,
    /// The CA's public key in OpenSSH format.
    pub public_key: String,
    /// SHA-256 fingerprint of the public key (`SHA256:...`).
    pub fingerprint: String,
}

/// The public trust bundle: everything an agent needs to trust certificates
/// this CA issues. Contains no private material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBundle {
    /// Monotonic CA generation counter (bumped on every lifecycle change).
    pub generation: u32,
    /// Deterministic SHA-256 fingerprint over the canonical bundle content.
    pub fingerprint: String,
    /// All enabled CA public keys, sorted by `key_id`.
    pub keys: Vec<CaPublicKeyEntry>,
}

/// A request to issue an SSH user certificate.
///
/// `principal` is the authenticated identity's username (GitHub login or OIDC
/// `preferred_username`); it is always derived from the authenticated identity,
/// never from the client request body, and becomes the certificate principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// Authenticated username; becomes the certificate principal.
    pub principal: String,
    /// Host the certificate is intended for (recorded for traceability).
    pub hostname: String,
    /// The user's OpenSSH-formatted public key to be signed.
    pub public_key: String,
    /// Requested lifetime in seconds. `0` selects [`DEFAULT_TTL_SECONDS`].
    pub ttl_seconds: u32,
}

/// The result of validating a certificate against this CA at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateValidation {
    /// `true` only if the certificate was issued by one of this CA's keys and
    /// is within its validity window at the evaluated time.
    pub valid: bool,
    /// Reason the certificate is not valid, if `valid` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the signature chains to one of this CA's keys.
    pub issued_by_this_ca: bool,
    /// Principals embedded in the certificate.
    pub principals: Vec<String>,
    /// Certificate serial number.
    pub serial: u64,
    /// RFC 3339 timestamp from which the certificate is valid.
    pub valid_after: String,
    /// RFC 3339 timestamp after which the certificate is invalid.
    pub valid_before: String,
}

/// The result of issuing a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateResponse {
    /// OpenSSH-formatted certificate (`ssh-ed25519-cert-v01@openssh.com ...`).
    pub certificate: String,
    /// Certificate serial number (unix epoch seconds at issuance).
    pub serial: u64,
    /// RFC 3339 timestamp from which the certificate is valid.
    pub valid_after: String,
    /// RFC 3339 timestamp after which the certificate is invalid.
    pub valid_before: String,
    /// Effective TTL applied, in seconds.
    pub ttl_seconds: u32,
    /// The principal embedded in the certificate.
    pub principal: String,
    /// SHA-256 fingerprint of the signed (subject) public key.
    pub fingerprint: String,
    /// Operator-assigned id of the CA that signed this certificate.
    pub ca_key_id: String,
    /// SHA-256 fingerprint of the CA that signed this certificate.
    pub ca_fingerprint: String,
}

/// Validate an operator-assigned `key_id`: non-empty, bounded, and limited to
/// printable identifier characters (so it is safe to embed in certificates and
/// canonical JSON).
pub fn validate_key_id(key_id: &str) -> Result<(), String> {
    let trimmed = key_id.trim();
    if trimmed.is_empty() {
        return Err("key_id must not be empty".to_string());
    }
    if trimmed.len() > MAX_KEY_ID_LEN {
        return Err(format!(
            "key_id must be at most {MAX_KEY_ID_LEN} characters"
        ));
    }
    if trimmed != key_id {
        return Err("key_id must not have leading or trailing whitespace".to_string());
    }
    let ok = key_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    if ok {
        Ok(())
    } else {
        Err("key_id may only contain alphanumerics and '-', '_', '.', ':'".to_string())
    }
}
