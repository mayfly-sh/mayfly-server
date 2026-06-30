//! Domain types for machine enrollment.
//!
//! Three groups of types live here:
//! - Persisted entities: [`Machine`] and [`EnrollmentToken`].
//! - Insert payloads the service hands to the repository: [`NewMachine`] and
//!   [`NewEnrollmentToken`].
//! - HTTP DTOs: [`EnrollRequest`] and [`EnrollResponse`].
//!
//! The enrollment *token* plaintext is never stored on any of these types; only
//! its SHA-256 hash is persisted (see [`crate::machines::token`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Lifecycle state of an enrolled machine.
///
/// Stored as a lowercase string. A freshly enrolled machine is [`Active`]: it
/// presented a valid single-use token, so there is nothing left to approve.
///
/// [`Active`]: MachineStatus::Active
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MachineStatus {
    /// Created but not yet activated (reserved for future approval flows).
    Pending,
    /// Enrolled and permitted to operate.
    Active,
    /// Temporarily prevented from operating.
    Disabled,
    /// Permanently revoked.
    Revoked,
}

impl MachineStatus {
    /// Stable lowercase string used in the database and audit log.
    pub fn as_str(&self) -> &'static str {
        match self {
            MachineStatus::Pending => "pending",
            MachineStatus::Active => "active",
            MachineStatus::Disabled => "disabled",
            MachineStatus::Revoked => "revoked",
        }
    }

    /// Parse a status from its stored string form.
    ///
    /// Returns `None` for any unrecognized value, which the repository treats
    /// as a corrupt row rather than silently defaulting.
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(MachineStatus::Pending),
            "active" => Some(MachineStatus::Active),
            "disabled" => Some(MachineStatus::Disabled),
            "revoked" => Some(MachineStatus::Revoked),
            _ => None,
        }
    }
}

/// A persisted, enrolled machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Machine {
    /// Server-issued identifier, e.g. `srv_3f0a…`.
    pub machine_id: String,
    /// The agent's reported hostname (unique across machines).
    pub hostname: String,
    /// The machine's OpenSSH Ed25519 public key (unique across machines).
    pub public_key: String,
    /// Reported operating system, e.g. `linux`.
    pub os: String,
    /// Reported CPU architecture, e.g. `x86_64`.
    pub arch: String,
    /// Reported agent version, e.g. `0.1.0`.
    pub agent_version: String,
    /// Current lifecycle status.
    pub status: MachineStatus,
    /// Last self-reported IP address, set on heartbeat. `None` until first seen.
    pub ip: Option<String>,
    /// Last self-reported configuration generation, set on heartbeat.
    pub current_generation: i64,
    /// The CA-bundle generation the agent last *successfully applied* (set by the
    /// bundle ack path). `None` until the first successful sync.
    pub synced_generation: Option<i64>,
    /// Fingerprint of the bundle the agent last applied. `None` until first sync.
    pub bundle_fingerprint: Option<String>,
    /// When the agent last successfully applied a bundle, if ever.
    pub last_sync: Option<DateTime<Utc>>,
    /// When the machine was last seen via heartbeat, if ever.
    pub last_seen: Option<DateTime<Utc>>,
    /// When enrollment completed.
    pub enrolled_at: DateTime<Utc>,
    /// When the row was created.
    pub created_at: DateTime<Utc>,
    /// When the row was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Fields required to insert a new machine.
///
/// The repository derives `created_at`/`updated_at`/`last_seen` from
/// `enrolled_at` so the timestamps are internally consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMachine {
    /// Server-issued identifier.
    pub machine_id: String,
    /// Reported hostname.
    pub hostname: String,
    /// OpenSSH Ed25519 public key.
    pub public_key: String,
    /// Reported operating system.
    pub os: String,
    /// Reported CPU architecture.
    pub arch: String,
    /// Reported agent version.
    pub agent_version: String,
    /// Initial lifecycle status.
    pub status: MachineStatus,
    /// Enrollment timestamp (also used for `created_at`/`updated_at`).
    pub enrolled_at: DateTime<Utc>,
}

/// A persisted enrollment token record.
///
/// Note there is no plaintext field: only [`EnrollmentToken::token_hash`] (a
/// SHA-256 hex digest) is ever stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentToken {
    /// Opaque token identifier (a UUID).
    pub id: String,
    /// SHA-256 hex digest of the plaintext token.
    pub token_hash: String,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
    /// When the token stops being valid.
    pub expires_at: DateTime<Utc>,
    /// When the token was consumed, if it has been.
    pub used_at: Option<DateTime<Utc>>,
    /// Identity that created the token (e.g. an admin GitHub login).
    pub created_by: String,
    /// Whether the token may be used only once.
    pub single_use: bool,
}

/// Fields required to insert a new enrollment token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEnrollmentToken {
    /// Opaque token identifier (a UUID).
    pub id: String,
    /// SHA-256 hex digest of the plaintext token.
    pub token_hash: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Identity that created the token.
    pub created_by: String,
    /// Whether the token may be used only once.
    pub single_use: bool,
}

/// A freshly issued enrollment token: the one-time plaintext plus its record.
///
/// The `plaintext` must be delivered to the operator and then discarded — it is
/// not recoverable from the stored record.
#[derive(Debug, Clone)]
pub struct IssuedEnrollmentToken {
    /// The one-time plaintext token (`mf_enroll_…`).
    pub plaintext: String,
    /// The persisted record (hash only).
    pub record: EnrollmentToken,
}

/// Request body for `POST /api/v1/machines/enroll`.
///
/// `Debug` is implemented by hand so the secret `enrollment_token` is never
/// printed in logs or panic messages.
#[derive(Clone, Deserialize)]
pub struct EnrollRequest {
    /// Single-use admission token (`mf_enroll_…`). Never logged or stored.
    pub enrollment_token: String,
    /// The machine's hostname.
    pub hostname: String,
    /// Reported operating system.
    pub os: String,
    /// Reported CPU architecture.
    pub arch: String,
    /// Reported agent version.
    pub agent_version: String,
    /// The machine's OpenSSH Ed25519 public key.
    pub public_key: String,
}

impl std::fmt::Debug for EnrollRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollRequest")
            .field("enrollment_token", &"<redacted>")
            .field("hostname", &self.hostname)
            .field("os", &self.os)
            .field("arch", &self.arch)
            .field("agent_version", &self.agent_version)
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Response body for a successful enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// The server-issued machine identifier.
    pub machine_id: String,
    /// Suggested heartbeat interval in seconds.
    pub heartbeat_interval: u32,
    /// Suggested CA-sync interval in seconds. Already jittered per host so the
    /// fleet does not poll in lockstep; the agent may apply further jitter.
    pub sync_interval: u32,
    /// The server's identity (its CA public key, OpenSSH Ed25519).
    pub server_identity: String,
    /// OpenSSH-format Ed25519 public key (`ssh-ed25519 AAAA...`) of the server's
    /// Bundle Signing Key. The agent pins this at enrollment and uses it to
    /// verify every signed CA bundle. `None` only if the server has no signing
    /// key configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_signing_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_db_string() {
        for status in [
            MachineStatus::Pending,
            MachineStatus::Active,
            MachineStatus::Disabled,
            MachineStatus::Revoked,
        ] {
            assert_eq!(MachineStatus::from_db_str(status.as_str()), Some(status));
        }
    }

    #[test]
    fn unknown_status_string_is_rejected() {
        assert_eq!(MachineStatus::from_db_str("bogus"), None);
    }

    #[test]
    fn enroll_request_debug_redacts_token() {
        let request = EnrollRequest {
            enrollment_token: "mf_enroll_supersecret".to_string(),
            hostname: "web-01".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            agent_version: "0.1.0".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("supersecret"));
        assert!(rendered.contains("web-01"));
    }

    #[test]
    fn enroll_response_serializes_to_expected_shape() {
        let response = EnrollResponse {
            machine_id: "srv_abc".to_string(),
            heartbeat_interval: 60,
            sync_interval: 300,
            server_identity: "ssh-ed25519 AAAA".to_string(),
            bundle_signing_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".to_string()),
        };
        let value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["machine_id"], "srv_abc");
        assert_eq!(value["heartbeat_interval"], 60);
        assert_eq!(value["sync_interval"], 300);
        assert_eq!(value["server_identity"], "ssh-ed25519 AAAA");
        assert_eq!(
            value["bundle_signing_key"],
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
        );
    }
}
