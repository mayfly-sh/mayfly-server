//! Hash-chain verification for the audit log.

use crate::audit::hash::{compute_entry_hash, hashes_equal, GENESIS_PREVIOUS_HASH};
use crate::audit::model::{AuditEntry, AuditVerificationResult};

/// Verify an audit chain ordered by ascending `chain_position`.
///
/// Each entry is checked for four properties, in order:
/// 1. `chain_position` equals its 1-based position (detects gaps / reordering),
/// 2. `previous_hash` links to the prior `entry_hash` (genesis for the first),
/// 3. the canonical form recomputed from the columns equals the stored
///    `canonical_json` (detects column tampering),
/// 4. `SHA256(canonical_json || previous_hash)` equals `entry_hash`.
///
/// Returns [`AuditVerificationResult::Broken`] at the first failing position,
/// otherwise [`AuditVerificationResult::Valid`].
pub fn verify_chain(entries: &[AuditEntry]) -> AuditVerificationResult {
    let mut expected_previous_hash = GENESIS_PREVIOUS_HASH.to_string();

    for (index, entry) in entries.iter().enumerate() {
        let expected_position = index as i64 + 1;
        if entry.chain_position != expected_position {
            return AuditVerificationResult::Broken {
                position: entry.chain_position,
                reason: format!(
                    "expected chain_position {expected_position}, found {}",
                    entry.chain_position
                ),
            };
        }

        if !hashes_equal(&entry.previous_hash, &expected_previous_hash) {
            return AuditVerificationResult::Broken {
                position: entry.chain_position,
                reason: "previous_hash does not match prior entry_hash".into(),
            };
        }

        match entry.recompute_canonical_json() {
            Ok(canonical) if canonical == entry.canonical_json => {}
            Ok(_) => {
                return AuditVerificationResult::Broken {
                    position: entry.chain_position,
                    reason: "canonical_json does not match stored columns".into(),
                };
            }
            Err(err) => {
                return AuditVerificationResult::Broken {
                    position: entry.chain_position,
                    reason: format!("failed to recompute canonical_json: {err}"),
                };
            }
        }

        let recomputed = compute_entry_hash(&entry.canonical_json, &entry.previous_hash);
        if !hashes_equal(&recomputed, &entry.entry_hash) {
            return AuditVerificationResult::Broken {
                position: entry.chain_position,
                reason: "entry_hash does not match recomputed digest".into(),
            };
        }

        expected_previous_hash = entry.entry_hash.clone();
    }

    AuditVerificationResult::Valid {
        entries_verified: entries.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::hash::{canonicalize, compute_entry_hash, GENESIS_PREVIOUS_HASH};
    use chrono::{DateTime, TimeZone, Utc};
    use proptest::prelude::*;
    use serde_json::{json, Value};

    fn ts(seq: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, (seq % 60) as u32)
            .unwrap()
    }

    fn build_entry(chain_position: i64, previous_hash: &str, metadata: Value) -> AuditEntry {
        let actor = format!("actor-{chain_position}");
        let subject = format!("subject-{chain_position}");
        let event_type = format!("event.{chain_position}");
        let recorded_at = ts(chain_position);
        let canonical_json = canonicalize(
            chain_position,
            &event_type,
            &actor,
            Some(&subject),
            &recorded_at,
            &metadata,
        )
        .expect("canonical");
        let entry_hash = compute_entry_hash(&canonical_json, previous_hash);

        AuditEntry {
            id: chain_position,
            chain_position,
            event_type,
            actor,
            subject: Some(subject),
            metadata,
            recorded_at,
            previous_hash: previous_hash.to_string(),
            canonical_json,
            entry_hash,
        }
    }

    fn build_chain(count: usize) -> Vec<AuditEntry> {
        let mut entries = Vec::with_capacity(count);
        let mut previous = GENESIS_PREVIOUS_HASH.to_string();
        for index in 0..count {
            let seq = (index + 1) as i64;
            let entry = build_entry(seq, &previous, json!({ "n": seq }));
            previous = entry.entry_hash.clone();
            entries.push(entry);
        }
        entries
    }

    #[test]
    fn valid_chain_verifies() {
        let chain = build_chain(3);
        assert!(matches!(
            verify_chain(&chain),
            AuditVerificationResult::Valid {
                entries_verified: 3
            }
        ));
    }

    #[test]
    fn empty_chain_is_valid() {
        assert!(matches!(
            verify_chain(&[]),
            AuditVerificationResult::Valid {
                entries_verified: 0
            }
        ));
    }

    #[test]
    fn genesis_must_link_to_genesis_hash() {
        let mut chain = build_chain(1);
        chain[0].previous_hash = "0".repeat(64);
        assert!(matches!(
            verify_chain(&chain),
            AuditVerificationResult::Broken { position: 1, .. }
        ));
    }

    #[test]
    fn detects_modified_column() {
        let mut chain = build_chain(2);
        // Tamper a business column without recomputing canonical/hash.
        chain[1].actor = "intruder".into();
        assert!(matches!(
            verify_chain(&chain),
            AuditVerificationResult::Broken { position: 2, .. }
        ));
    }

    #[test]
    fn detects_modified_canonical_json() {
        let mut chain = build_chain(2);
        chain[1].canonical_json = "{\"tampered\":true}".into();
        assert!(matches!(
            verify_chain(&chain),
            AuditVerificationResult::Broken { position: 2, .. }
        ));
    }

    #[test]
    fn detects_modified_entry_hash() {
        let mut chain = build_chain(2);
        chain[1].entry_hash = "0".repeat(64);
        assert!(matches!(
            verify_chain(&chain),
            AuditVerificationResult::Broken { position: 2, .. }
        ));
    }

    #[test]
    fn detects_broken_previous_hash_link() {
        let mut chain = build_chain(2);
        chain[1].previous_hash = "0".repeat(64);
        assert!(matches!(
            verify_chain(&chain),
            AuditVerificationResult::Broken { position: 2, .. }
        ));
    }

    #[test]
    fn detects_deleted_entry_gap() {
        let chain = build_chain(3);
        let without_middle = vec![chain[0].clone(), chain[2].clone()];
        // Position 2 now holds the entry whose chain_position is 3.
        assert!(matches!(
            verify_chain(&without_middle),
            AuditVerificationResult::Broken { position: 3, .. }
        ));
    }

    #[test]
    fn detects_reordered_entries() {
        let chain = build_chain(3);
        let reordered = vec![chain[0].clone(), chain[2].clone(), chain[1].clone()];
        assert!(!verify_chain(&reordered).is_valid());
    }

    proptest! {
        #[test]
        fn arbitrary_valid_chains_always_verify(count in 1usize..25) {
            prop_assert!(verify_chain(&build_chain(count)).is_valid());
        }

        #[test]
        fn arbitrary_mutation_breaks_chain(
            count in 2usize..12,
            mutation_index in 0usize..11,
        ) {
            let mut chain = build_chain(count);
            let index = mutation_index % count;
            chain[index].actor = format!("mutated-{index}");
            prop_assert!(!verify_chain(&chain).is_valid());
        }
    }
}
