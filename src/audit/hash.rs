//! Hash-chain computation for tamper-evident audit entries.

use crate::audit::model::AuditHashInput;
use crate::errors::AuditError;
use sha2::{Digest, Sha256};

/// Fixed `previous_hash` for the genesis entry at `chain_position = 1`.
///
/// Defined as `SHA256("mayfly-audit-genesis-v1")` hex-encoded.
pub const GENESIS_PREVIOUS_HASH: &str =
    "df245b05e4a1ca45e4eb8a6e002f84f9abf9f22dd751b84129c351546d02656b";

/// Compute the entry hash for an audit log link.
///
/// `entry_hash = SHA256(canonical_json || previous_hash)` where `canonical_json`
/// is the deterministic JSON serialization of [`AuditHashInput`].
pub fn compute_entry_hash(
    input: &AuditHashInput,
    previous_hash: &str,
) -> Result<String, AuditError> {
    let canonical_json = serde_json::to_string(input)
        .map_err(|err| AuditError::Hash(format!("failed to serialize hash input: {err}")))?;

    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    hasher.update(previous_hash.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Compare two hex-encoded hashes in constant time.
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
    use crate::audit::model::AuditHashInput;

    fn sample_input() -> AuditHashInput {
        AuditHashInput {
            serial: "01".into(),
            username: "alice".into(),
            github_login: "alice-github".into(),
            hostname: "web-01".into(),
            issued_at: "2026-06-24T12:00:00Z".into(),
            ttl_seconds: 3600,
            cert_fingerprint: "abc123".into(),
        }
    }

    #[test]
    fn genesis_constant_matches_documented_digest() {
        let digest = Sha256::digest(b"mayfly-audit-genesis-v1");
        assert_eq!(GENESIS_PREVIOUS_HASH, hex::encode(digest));
    }

    #[test]
    fn hash_generation_is_deterministic() {
        let input = sample_input();
        let first = compute_entry_hash(&input, GENESIS_PREVIOUS_HASH).expect("hash");
        let second = compute_entry_hash(&input, GENESIS_PREVIOUS_HASH).expect("hash");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn hash_changes_when_previous_hash_changes() {
        let input = sample_input();
        let genesis = compute_entry_hash(&input, GENESIS_PREVIOUS_HASH).expect("hash");
        let other = compute_entry_hash(&input, "deadbeef".repeat(8).as_str()).expect("hash");
        assert_ne!(genesis, other);
    }

    #[test]
    fn hash_changes_when_canonical_field_changes() {
        let mut input = sample_input();
        let baseline = compute_entry_hash(&input, GENESIS_PREVIOUS_HASH).expect("hash");

        input.serial = "02".into();
        let mutated = compute_entry_hash(&input, GENESIS_PREVIOUS_HASH).expect("hash");
        assert_ne!(baseline, mutated);
    }
}
