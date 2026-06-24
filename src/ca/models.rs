//! Certificate issuance request/response types and signing bounds.

use serde::{Deserialize, Serialize};

/// Minimum accepted certificate TTL, in seconds.
pub const MIN_TTL_SECONDS: u32 = 60;
/// Maximum accepted certificate TTL, in seconds.
pub const MAX_TTL_SECONDS: u32 = 3600;
/// Default TTL applied when a request specifies `ttl_seconds == 0`.
pub const DEFAULT_TTL_SECONDS: u32 = 300;

/// A request to issue an SSH user certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// GitHub login of the requester; becomes the default certificate principal.
    pub github_login: String,
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
    /// `true` only if the certificate was issued by this CA and is within its
    /// validity window at the evaluated time.
    pub valid: bool,
    /// Reason the certificate is not valid, if `valid` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the signature chains to this CA's key.
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
}
