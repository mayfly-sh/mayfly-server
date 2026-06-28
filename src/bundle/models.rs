//! Wire and domain types for the signed CA bundle distribution protocol.
//!
//! The [`SignedBundle`] is the production-grade replacement for the bare key
//! list previously served at `GET /api/v1/agent/ca-bundle`. It carries the same
//! trust material (the enabled CA public keys) plus the metadata an agent needs
//! to verify *authenticity* (a detached Ed25519 signature over a canonical
//! representation) and *freshness* (`created_at` / `expires_at`).
//!
//! The fingerprint still *identifies* a bundle (and is the HTTP `ETag`); the
//! signature *authenticates* it. These are independent: the fingerprint is a
//! content digest anyone can recompute, the signature requires the server's
//! Bundle Signing Key.

use serde::{Deserialize, Serialize};

/// The only bundle schema version this server produces and the only one agents
/// must accept. Bump (and add a new canonicalization arm) for breaking changes.
pub const BUNDLE_VERSION: u32 = 1;

/// The signature algorithm used for the Bundle Signing Key. Ed25519 only.
pub const SIGNATURE_ALGORITHM: &str = "ssh-ed25519";

/// One enabled CA public key as published in a [`SignedBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleKey {
    /// Operator-assigned key identifier.
    pub key_id: String,
    /// The CA's public key in OpenSSH format (what an agent writes into
    /// `TrustedUserCAKeys`).
    pub public_key: String,
    /// SHA-256 fingerprint of `public_key` (`SHA256:...`), for display only.
    pub fingerprint: String,
}

/// A signed, versioned CA trust bundle.
///
/// Field order here is *not* significant for the signature: the signature
/// covers the canonical byte representation produced by
/// [`crate::bundle::canonical`], never this struct's serialized JSON. The
/// agent reconstructs the canonical bytes from the parsed fields and verifies
/// against the pinned Bundle Signing Key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBundle {
    /// Schema version (`1`). Agents MUST reject unknown versions.
    pub bundle_version: u32,
    /// Monotonic CA generation counter.
    pub generation: u32,
    /// RFC 3339 instant the bundle was signed.
    pub created_at: String,
    /// RFC 3339 instant after which the bundle must not be trusted.
    pub expires_at: String,
    /// Content fingerprint (`sha256:<hex>`); also the HTTP `ETag`.
    pub fingerprint: String,
    /// Enabled CA public keys, sorted by `key_id`.
    pub keys: Vec<BundleKey>,
    /// Signature algorithm identifier (`ssh-ed25519`).
    pub signature_algorithm: String,
    /// Base64 detached signature over the canonical representation.
    pub signature: String,
    /// OpenSSH-format Ed25519 public key of the Bundle Signing Key
    /// (`ssh-ed25519 AAAA...`), for convenience. Agents MUST still pin this key
    /// out of band (delivered at enrollment) and MUST NOT trust a bundle solely
    /// because it carries a self-consistent key.
    pub bundle_signing_public_key: String,
}

/// Errors from building, signing, or verifying a [`SignedBundle`].
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The bundle declares a schema version this build does not support.
    #[error("unsupported bundle version '{0}'")]
    UnsupportedVersion(String),

    /// The bundle's signature algorithm is not supported.
    #[error("unsupported signature algorithm '{0}'")]
    UnsupportedAlgorithm(String),

    /// A field (signature, public key, timestamp) was not parseable.
    #[error("malformed bundle: {0}")]
    Malformed(String),

    /// The signature did not verify against the pinned signing key.
    #[error("bundle signature verification failed")]
    SignatureInvalid,

    /// The signing key embedded in the bundle does not match the pinned key.
    #[error("bundle was signed by an unexpected key")]
    UntrustedSigner,

    /// `now` is past `expires_at`.
    #[error("bundle has expired")]
    Expired,

    /// There are no enabled CA keys to publish.
    #[error("cannot build a bundle: no enabled CA keys")]
    NoEnabledKeys,

    /// A cryptographic primitive failed unexpectedly.
    #[error("bundle crypto error: {0}")]
    Crypto(String),
}

/// The acknowledgement outcome an agent reports after attempting to apply a
/// bundle. Mirrors the agent's local apply/rollback state machine and drives
/// the corresponding audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// The agent verified, wrote, and reloaded `sshd` successfully.
    Applied,
    /// The agent rolled back to the previous bundle after a failed reload.
    RolledBack,
    /// The agent rejected the bundle because signature verification failed.
    SignatureFailed,
}

impl AckOutcome {
    /// Parse the wire `status` string. Unknown values are rejected.
    pub fn parse(status: &str) -> Option<Self> {
        match status.trim().to_ascii_lowercase().as_str() {
            // "success" retained for backwards compatibility with the prior ack.
            "applied" | "success" => Some(Self::Applied),
            "rollback" | "rolled_back" => Some(Self::RolledBack),
            "signature_failed" => Some(Self::SignatureFailed),
            _ => None,
        }
    }

    /// The audit `event_type` recorded for this outcome.
    pub fn audit_event(self) -> &'static str {
        match self {
            Self::Applied => "bundle.applied",
            Self::RolledBack => "bundle.rollback",
            Self::SignatureFailed => "bundle.signature_failed",
        }
    }

    /// Whether this outcome means the machine is now on the acknowledged
    /// generation (only a successful apply updates `synced_generation`).
    pub fn is_success(self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// Request body for `POST /api/v1/agent/ca-bundle/ack`.
#[derive(Debug, Clone, Deserialize)]
pub struct BundleAckRequest {
    /// The generation the agent attempted to apply.
    pub generation: i64,
    /// The fingerprint the agent attempted to apply.
    pub fingerprint: String,
    /// Outcome status: `applied` / `rollback` / `signature_failed`.
    pub status: String,
    /// Optional human-readable detail (e.g. reload error). Never a secret.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Response body for a recorded acknowledgement.
#[derive(Debug, Clone, Serialize)]
pub struct BundleAckResponse {
    /// Always `"recorded"`.
    pub status: &'static str,
    /// The acknowledged generation.
    pub generation: i64,
}

/// Count of machines reporting a given synced generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GenerationCount {
    /// The synced generation.
    pub generation: i64,
    /// Number of machines currently on that generation.
    pub count: i64,
}

/// Fleet rollout visibility for `GET /api/v1/admin/bundle/status`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FleetStatus {
    /// The server's current (latest) generation.
    pub latest_generation: u32,
    /// Total enrolled machines.
    pub total_machines: i64,
    /// Machines whose last heartbeat is within the ONLINE window.
    pub online: i64,
    /// Machines seen recently but past the ONLINE window.
    pub stale: i64,
    /// Machines not seen within the STALE window (or never seen).
    pub offline: i64,
    /// Percentage (0–100) of machines whose synced generation equals
    /// `latest_generation`, rounded to one decimal place.
    pub rollout_percentage: f64,
    /// Oldest synced generation observed across the fleet, if any machine has
    /// acknowledged a bundle.
    pub oldest_generation: Option<i64>,
    /// Newest synced generation observed across the fleet, if any.
    pub newest_generation: Option<i64>,
    /// Per-generation machine counts, ascending by generation.
    pub generations: Vec<GenerationCount>,
}

/// Whether a CA key can be safely retired, and the evidence behind that call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetirementAssessment {
    /// The CA's stable id.
    pub id: String,
    /// The CA's operator-assigned key id.
    pub key_id: String,
    /// `"safe"` or `"unsafe"`.
    pub safety: &'static str,
    /// Convenience boolean mirror of [`Self::safety`].
    pub safe: bool,
    /// Number of enrolled machines that may still depend on this key (synced a
    /// generation older than the one that removed it, or never synced).
    pub affected_machines: i64,
    /// Oldest synced generation among affected machines, if any.
    pub oldest_generation: Option<i64>,
    /// Newest synced generation among affected machines, if any.
    pub latest_generation: Option<i64>,
    /// Human-readable explanation of the verdict.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_outcome_parses_known_statuses_case_insensitively() {
        assert_eq!(AckOutcome::parse("applied"), Some(AckOutcome::Applied));
        assert_eq!(AckOutcome::parse("SUCCESS"), Some(AckOutcome::Applied));
        assert_eq!(AckOutcome::parse("rollback"), Some(AckOutcome::RolledBack));
        assert_eq!(
            AckOutcome::parse(" signature_failed "),
            Some(AckOutcome::SignatureFailed)
        );
        assert_eq!(AckOutcome::parse("nonsense"), None);
    }

    #[test]
    fn ack_outcome_maps_to_audit_events() {
        assert_eq!(AckOutcome::Applied.audit_event(), "bundle.applied");
        assert_eq!(AckOutcome::RolledBack.audit_event(), "bundle.rollback");
        assert_eq!(
            AckOutcome::SignatureFailed.audit_event(),
            "bundle.signature_failed"
        );
        assert!(AckOutcome::Applied.is_success());
        assert!(!AckOutcome::RolledBack.is_success());
    }

    /// Protocol: the serialized [`SignedBundle`] exposes the exact wire field
    /// names and JSON types the agent's `CaBundleResponse` deserializes —
    /// `bundle_version` as an integer, `signature_algorithm` as `ssh-ed25519`,
    /// and the signing key under `bundle_signing_public_key` in OpenSSH form.
    #[test]
    fn signed_bundle_serializes_with_wire_field_names() {
        let bundle = SignedBundle {
            bundle_version: BUNDLE_VERSION,
            generation: 42,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-02-01T00:00:00Z".to_string(),
            fingerprint: "sha256:ab".to_string(),
            keys: vec![BundleKey {
                key_id: "ca-01".to_string(),
                public_key: "ssh-ed25519 AAAA".to_string(),
                fingerprint: "SHA256:x".to_string(),
            }],
            signature_algorithm: SIGNATURE_ALGORITHM.to_string(),
            signature: "c2ln".to_string(),
            bundle_signing_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".to_string(),
        };
        let value = serde_json::to_value(&bundle).expect("serialize");
        assert_eq!(value["bundle_version"], 1);
        assert!(value["bundle_version"].is_u64());
        assert_eq!(value["signature_algorithm"], "ssh-ed25519");
        assert_eq!(
            value["bundle_signing_public_key"],
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
        );
        assert_eq!(value["keys"][0]["key_id"], "ca-01");
        // The legacy field name must not be present.
        assert!(value.get("signing_public_key").is_none());
    }

    /// Protocol: the server deserializes the agent's exact ack bytes (the bytes
    /// asserted by the agent's `ack_report_serializes_to_server_schema` test)
    /// without any aliases — applied omits `reason`, rollback carries it.
    #[test]
    fn deserializes_agent_ack_bytes() {
        let applied: BundleAckRequest = serde_json::from_str(
            "{\"generation\":42,\"fingerprint\":\"sha256:ab\",\"status\":\"applied\"}",
        )
        .expect("applied ack");
        assert_eq!(applied.generation, 42);
        assert_eq!(applied.fingerprint, "sha256:ab");
        assert_eq!(
            AckOutcome::parse(&applied.status),
            Some(AckOutcome::Applied)
        );
        assert!(applied.reason.is_none());

        let rollback: BundleAckRequest = serde_json::from_str(
            "{\"generation\":42,\"fingerprint\":\"sha256:ab\",\"status\":\"rollback\",\
\"reason\":\"sshd reload failed; previous bundle restored\"}",
        )
        .expect("rollback ack");
        assert_eq!(
            AckOutcome::parse(&rollback.status),
            Some(AckOutcome::RolledBack)
        );
        assert_eq!(
            rollback.reason.as_deref(),
            Some("sshd reload failed; previous bundle restored")
        );
    }
}
