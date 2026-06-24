//! Audit log domain types.

use serde::{Deserialize, Serialize};

/// Canonical payload hashed for each audit entry.
///
/// Field order is fixed by struct declaration so `serde_json` output is stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHashInput {
    /// Certificate serial number.
    pub serial: String,
    /// Unix username granted by the certificate.
    pub username: String,
    /// GitHub login of the requester.
    pub github_login: String,
    /// Target host the certificate is valid for.
    pub hostname: String,
    /// ISO 8601 timestamp when the certificate was issued.
    pub issued_at: String,
    /// Certificate time-to-live in seconds.
    pub ttl_seconds: i64,
    /// SHA-256 fingerprint of the issued certificate.
    pub cert_fingerprint: String,
}

/// Fields required to append a new audit log entry (hashes computed on insert).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditLogEntry {
    pub serial: String,
    pub username: String,
    pub github_login: String,
    pub hostname: String,
    pub issued_at: String,
    pub hashed_at: String,
    pub ttl_seconds: i64,
    pub requester_ip: Option<String>,
    pub cert_fingerprint: String,
}

impl NewAuditLogEntry {
    /// Build the canonical hash input from issuance metadata.
    pub fn hash_input(&self) -> AuditHashInput {
        AuditHashInput {
            serial: self.serial.clone(),
            username: self.username.clone(),
            github_login: self.github_login.clone(),
            hostname: self.hostname.clone(),
            issued_at: self.issued_at.clone(),
            ttl_seconds: self.ttl_seconds,
            cert_fingerprint: self.cert_fingerprint.clone(),
        }
    }
}

/// A persisted audit log entry including hash-chain metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub id: i64,
    pub chain_position: i64,
    pub serial: String,
    pub username: String,
    pub github_login: String,
    pub hostname: String,
    pub issued_at: String,
    pub hashed_at: String,
    pub ttl_seconds: i64,
    pub requester_ip: Option<String>,
    pub cert_fingerprint: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

impl AuditLogEntry {
    /// Build the canonical hash input from a stored entry.
    pub fn hash_input(&self) -> AuditHashInput {
        AuditHashInput {
            serial: self.serial.clone(),
            username: self.username.clone(),
            github_login: self.github_login.clone(),
            hostname: self.hostname.clone(),
            issued_at: self.issued_at.clone(),
            ttl_seconds: self.ttl_seconds,
            cert_fingerprint: self.cert_fingerprint.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_new_entry() -> NewAuditLogEntry {
        NewAuditLogEntry {
            serial: "01".into(),
            username: "alice".into(),
            github_login: "alice-github".into(),
            hostname: "web-01".into(),
            issued_at: "2026-06-24T12:00:00Z".into(),
            hashed_at: "2026-06-24T12:00:01Z".into(),
            ttl_seconds: 3600,
            requester_ip: Some("203.0.113.10".into()),
            cert_fingerprint: "abc123".into(),
        }
    }

    #[test]
    fn hash_input_excludes_non_canonical_fields() {
        let entry = sample_new_entry();
        let input = entry.hash_input();
        assert_eq!(input.serial, "01");
        assert_eq!(input.username, "alice");
        assert_eq!(input.ttl_seconds, 3600);
    }
}
