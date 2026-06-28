//! Audit log domain types.
//!
//! The audit log is a generic, tamper-evident record of security events. An
//! event is described by an `event_type`, the `actor` that triggered it, an
//! optional `subject` (the target), and free-form structured `metadata`.
//! Certificate issuance, OAuth logins, and policy changes will all be recorded
//! as events with different `event_type`s rather than bespoke tables.

use crate::audit::hash;
use crate::errors::AuditError;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Fields a caller provides to record a new audit event.
///
/// The chain metadata (`chain_position`, `previous_hash`, `canonical_json`,
/// `entry_hash`) and the persistence timestamp (`recorded_at`) are assigned by
/// the service and repository — callers never supply them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEntry {
    /// Dotted event identifier, e.g. `"certificate.issued"`.
    pub event_type: String,
    /// Who or what triggered the event, e.g. a GitHub login or `"system"`.
    pub actor: String,
    /// Optional target of the action, e.g. a hostname or certificate serial.
    pub subject: Option<String>,
    /// Structured, event-specific detail. Object keys are serialized in sorted
    /// order, so canonicalization is independent of insertion order.
    pub metadata: Value,
}

impl NewAuditEntry {
    /// Build an event with no subject and empty (`null`) metadata.
    pub fn new(event_type: impl Into<String>, actor: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            actor: actor.into(),
            subject: None,
            metadata: Value::Null,
        }
    }

    /// Set the event subject (the target of the action).
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Attach structured metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// A persisted audit entry, including its hash-chain metadata.
///
/// Invariant enforced by [`crate::audit::verifier`]: `canonical_json` is the
/// deterministic serialization of every business column, and `entry_hash =
/// SHA256(canonical_json || previous_hash)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// SQLite rowid (storage detail; not part of the hash).
    pub id: i64,
    /// 1-based position in the chain.
    pub chain_position: i64,
    /// Dotted event identifier.
    pub event_type: String,
    /// Who or what triggered the event.
    pub actor: String,
    /// Optional target of the action.
    pub subject: Option<String>,
    /// Structured, event-specific detail.
    pub metadata: Value,
    /// When the event was recorded, truncated to millisecond precision.
    pub recorded_at: DateTime<Utc>,
    /// `entry_hash` of the preceding entry, or the genesis hash for the first.
    pub previous_hash: String,
    /// Stored canonical serialization of this entry's business columns.
    pub canonical_json: String,
    /// `SHA256(canonical_json || previous_hash)`, hex-encoded.
    pub entry_hash: String,
}

impl AuditEntry {
    /// Recompute the canonical JSON from this entry's business columns.
    ///
    /// Used by verification to detect column-level tampering: the result must
    /// equal the stored [`AuditEntry::canonical_json`].
    pub fn recompute_canonical_json(&self) -> Result<String, AuditError> {
        hash::canonicalize(
            self.chain_position,
            &self.event_type,
            &self.actor,
            self.subject.as_deref(),
            &self.recorded_at,
            &self.metadata,
        )
    }
}

/// The current head of the audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTip {
    /// Chain position of the latest entry.
    pub chain_position: i64,
    /// `entry_hash` of the latest entry — the value the next append links to.
    pub entry_hash: String,
}

/// Outcome of verifying the audit chain.
///
/// A broken chain is a *finding*, not an error; operational failures while
/// loading the chain are reported separately as [`AuditError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerificationResult {
    /// Every link verified successfully.
    Valid {
        /// Number of entries checked.
        entries_verified: u64,
    },
    /// The chain is broken at `position`.
    Broken {
        /// Sequence at which the first failure was detected.
        position: i64,
        /// Human-readable explanation of the failure.
        reason: String,
    },
}

impl AuditVerificationResult {
    /// `true` when the chain verified successfully.
    pub fn is_valid(&self) -> bool {
        matches!(self, AuditVerificationResult::Valid { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_subject_and_metadata() {
        let entry = NewAuditEntry::new("certificate.issued", "octocat")
            .with_subject("web-01")
            .with_metadata(serde_json::json!({ "serial": "01" }));

        assert_eq!(entry.event_type, "certificate.issued");
        assert_eq!(entry.actor, "octocat");
        assert_eq!(entry.subject.as_deref(), Some("web-01"));
        assert_eq!(entry.metadata["serial"], "01");
    }

    #[test]
    fn verification_result_is_valid_helper() {
        assert!(AuditVerificationResult::Valid {
            entries_verified: 3
        }
        .is_valid());
        assert!(!AuditVerificationResult::Broken {
            position: 2,
            reason: "x".into()
        }
        .is_valid());
    }
}
