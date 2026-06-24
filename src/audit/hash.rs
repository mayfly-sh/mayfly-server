//! Deterministic canonicalization and hash-chain computation.
//!
//! `entry_hash = SHA256(canonical_json || previous_hash)`, where
//! `canonical_json` is the serialization of [`Canonical`] — a fixed-field-order
//! struct covering every business column. `serde_json::Value::Object` is a
//! `BTreeMap`, so nested metadata keys are emitted in sorted order and the
//! canonical form is independent of how the metadata was constructed.

use crate::errors::AuditError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Fixed `previous_hash` for the genesis entry at `chain_position = 1`.
///
/// Defined as `SHA256("mayfly-audit-genesis-v1")`, hex-encoded.
pub const GENESIS_PREVIOUS_HASH: &str =
    "df245b05e4a1ca45e4eb8a6e002f84f9abf9f22dd751b84129c351546d02656b";

/// Canonical, hashable view of an audit entry's business columns.
///
/// Field order is fixed by declaration; `serde_json` preserves struct field
/// order, giving a stable byte representation.
#[derive(Debug, Serialize)]
struct Canonical<'a> {
    chain_position: i64,
    event_type: &'a str,
    actor: &'a str,
    subject: Option<&'a str>,
    recorded_at: String,
    metadata: &'a Value,
}

/// Produce the deterministic canonical JSON for an entry's business columns.
///
/// `recorded_at` is rendered as RFC 3339 with millisecond precision, matching
/// what is persisted, so a re-read entry canonicalizes identically.
pub fn canonicalize(
    chain_position: i64,
    event_type: &str,
    actor: &str,
    subject: Option<&str>,
    recorded_at: &DateTime<Utc>,
    metadata: &Value,
) -> Result<String, AuditError> {
    let canonical = Canonical {
        chain_position,
        event_type,
        actor,
        subject,
        recorded_at: recorded_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        metadata,
    };

    serde_json::to_string(&canonical)
        .map_err(|err| AuditError::Serialization(format!("failed to serialize canonical entry: {err}")))
}

/// Compute the hex-encoded `entry_hash` for an entry.
pub fn compute_entry_hash(canonical_json: &str, previous_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    hasher.update(previous_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compare two hex-encoded hashes in constant time (length-dependent only).
pub fn hashes_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap()
    }

    #[test]
    fn genesis_constant_matches_documented_digest() {
        let digest = Sha256::digest(b"mayfly-audit-genesis-v1");
        assert_eq!(GENESIS_PREVIOUS_HASH, hex::encode(digest));
    }

    #[test]
    fn canonicalization_is_deterministic() {
        let meta = json!({ "serial": "01", "ttl": 3600 });
        let a = canonicalize(1, "cert.issued", "octocat", Some("web-01"), &ts(), &meta).unwrap();
        let b = canonicalize(1, "cert.issued", "octocat", Some("web-01"), &ts(), &meta).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonicalization_is_independent_of_metadata_key_order() {
        // Same logical object, different source key order. `serde_json::Value`
        // stores objects in a BTreeMap, so both canonicalize identically.
        let first: Value = serde_json::from_str(r#"{"b":1,"a":2,"c":3}"#).unwrap();
        let second: Value = serde_json::from_str(r#"{"c":3,"a":2,"b":1}"#).unwrap();

        let a = canonicalize(1, "e", "x", None, &ts(), &first).unwrap();
        let b = canonicalize(1, "e", "x", None, &ts(), &second).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_changes_when_canonical_changes() {
        let baseline = compute_entry_hash("{\"a\":1}", GENESIS_PREVIOUS_HASH);
        let mutated = compute_entry_hash("{\"a\":2}", GENESIS_PREVIOUS_HASH);
        assert_ne!(baseline, mutated);
        assert_eq!(baseline.len(), 64);
    }

    #[test]
    fn hash_changes_when_previous_hash_changes() {
        let canonical = "{\"a\":1}";
        let a = compute_entry_hash(canonical, GENESIS_PREVIOUS_HASH);
        let b = compute_entry_hash(canonical, &"0".repeat(64));
        assert_ne!(a, b);
    }

    #[test]
    fn hashes_equal_is_correct() {
        assert!(hashes_equal("abcd", "abcd"));
        assert!(!hashes_equal("abcd", "abce"));
        assert!(!hashes_equal("abcd", "abcde"));
    }
}
