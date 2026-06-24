//! Hash-chain verification for the audit log.

use crate::audit::hash::{compute_entry_hash, hashes_equal, GENESIS_PREVIOUS_HASH};
use crate::audit::model::AuditLogEntry;
use crate::errors::AuditError;

/// Verify an in-memory audit chain ordered by ascending `chain_position`.
///
/// Returns `Ok(())` when every link is valid. On failure, returns
/// [`AuditError::ChainBroken`] with the first broken `chain_position`.
pub fn verify_chain(entries: &[AuditLogEntry]) -> Result<(), AuditError> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut expected_previous_hash = GENESIS_PREVIOUS_HASH.to_string();

    for (index, entry) in entries.iter().enumerate() {
        let expected_position = index as i64 + 1;
        if entry.chain_position != expected_position {
            return Err(AuditError::ChainBroken {
                position: entry.chain_position,
                reason: format!(
                    "expected chain_position {expected_position}, found {}",
                    entry.chain_position
                ),
            });
        }

        if !hashes_equal(&entry.previous_hash, &expected_previous_hash) {
            return Err(AuditError::ChainBroken {
                position: entry.chain_position,
                reason: "previous_hash does not match prior entry_hash".into(),
            });
        }

        let recomputed =
            compute_entry_hash(&entry.hash_input(), &entry.previous_hash).map_err(|err| {
                AuditError::ChainBroken {
                    position: entry.chain_position,
                    reason: err.to_string(),
                }
            })?;

        if !hashes_equal(&recomputed, &entry.entry_hash) {
            return Err(AuditError::ChainBroken {
                position: entry.chain_position,
                reason: "entry_hash does not match recomputed digest".into(),
            });
        }

        expected_previous_hash = entry.entry_hash.clone();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::hash::{compute_entry_hash, GENESIS_PREVIOUS_HASH};
    use crate::audit::model::{AuditLogEntry, NewAuditLogEntry};
    use proptest::prelude::*;

    fn build_entry(
        chain_position: i64,
        previous_hash: &str,
        new_entry: &NewAuditLogEntry,
    ) -> AuditLogEntry {
        let entry_hash =
            compute_entry_hash(&new_entry.hash_input(), previous_hash).expect("hash");

        AuditLogEntry {
            id: chain_position,
            chain_position,
            serial: new_entry.serial.clone(),
            username: new_entry.username.clone(),
            github_login: new_entry.github_login.clone(),
            hostname: new_entry.hostname.clone(),
            issued_at: new_entry.issued_at.clone(),
            hashed_at: new_entry.hashed_at.clone(),
            ttl_seconds: new_entry.ttl_seconds,
            requester_ip: new_entry.requester_ip.clone(),
            cert_fingerprint: new_entry.cert_fingerprint.clone(),
            previous_hash: previous_hash.to_string(),
            entry_hash,
        }
    }

    fn build_chain(count: usize) -> Vec<AuditLogEntry> {
        let mut entries = Vec::with_capacity(count);
        let mut previous_hash = GENESIS_PREVIOUS_HASH.to_string();

        for index in 0..count {
            let position = (index + 1) as i64;
            let new_entry = NewAuditLogEntry {
                serial: format!("serial-{position}"),
                username: format!("user-{position}"),
                github_login: format!("gh-{position}"),
                hostname: format!("host-{position}"),
                issued_at: format!("2026-06-24T12:00:{position:02}Z"),
                hashed_at: format!("2026-06-24T12:00:{position:02}Z"),
                ttl_seconds: 3600 + position,
                requester_ip: Some(format!("203.0.113.{position}")),
                cert_fingerprint: format!("fp-{position}"),
            };

            let entry = build_entry(position, &previous_hash, &new_entry);
            previous_hash = entry.entry_hash.clone();
            entries.push(entry);
        }

        entries
    }

    #[test]
    fn verify_valid_chain() {
        let chain = build_chain(3);
        verify_chain(&chain).expect("valid chain");
    }

    #[test]
    fn verify_empty_chain() {
        verify_chain(&[]).expect("empty chain is valid");
    }

    #[test]
    fn detect_modified_entry_hash() {
        let mut chain = build_chain(2);
        chain[1].entry_hash = "0".repeat(64);
        let err = verify_chain(&chain).expect_err("modified hash");
        assert!(matches!(
            err,
            AuditError::ChainBroken { position: 2, .. }
        ));
    }

    #[test]
    fn detect_modified_canonical_field() {
        let mut chain = build_chain(2);
        chain[1].username = "tampered".into();
        let err = verify_chain(&chain).expect_err("modified field");
        assert!(matches!(
            err,
            AuditError::ChainBroken { position: 2, .. }
        ));
    }

    #[test]
    fn detect_deleted_entry_gap() {
        let chain = build_chain(3);
        let without_middle = vec![chain[0].clone(), chain[2].clone()];
        let err = verify_chain(&without_middle).expect_err("gap");
        assert!(matches!(
            err,
            AuditError::ChainBroken { position: 3, .. }
        ));
    }

    #[test]
    fn detect_broken_previous_hash_link() {
        let mut chain = build_chain(2);
        chain[1].previous_hash = "0".repeat(64);
        let err = verify_chain(&chain).expect_err("broken link");
        assert!(matches!(
            err,
            AuditError::ChainBroken { position: 2, .. }
        ));
    }

    proptest! {
        #[test]
        fn arbitrary_valid_chains_always_verify(count in 1usize..20) {
            let chain = build_chain(count);
            verify_chain(&chain).expect("valid chain");
        }

        #[test]
        fn arbitrary_mutation_causes_verification_failure(
            count in 2usize..10,
            mutation_index in 0usize..9,
        ) {
            let mut chain = build_chain(count);
            let index = mutation_index % count;
            chain[index].serial = "mutated-serial".into();
            prop_assert!(verify_chain(&chain).is_err());
        }
    }
}
