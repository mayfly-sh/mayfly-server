//! Enrollment-token cryptography: generation, hashing, and comparison.
//!
//! Tokens look like `mf_enroll_<hex>` where `<hex>` is 32 bytes (256 bits) of
//! CSPRNG output, hex-encoded. Only the SHA-256 hash of the full token string
//! is ever persisted; the plaintext is returned to the operator once and then
//! forgotten.
//!
//! All comparisons of hashes use [`constant_time_eq`] so a timing side channel
//! cannot be used to recover a stored hash byte by byte.

use sha2::{Digest, Sha256};
use ssh_key::rand_core::{OsRng, RngCore};

/// Required prefix for enrollment tokens.
pub const TOKEN_PREFIX: &str = "mf_enroll_";

/// Entropy of the random portion of a token, in bytes (256 bits).
pub const TOKEN_ENTROPY_BYTES: usize = 32;

/// Upper bound on accepted token length (defensive; well above what we mint).
const MAX_TOKEN_LEN: usize = 256;

/// Generate a fresh enrollment token with at least 256 bits of entropy.
///
/// Returns the plaintext token; callers hash it with [`hash_token`] for
/// storage and hand the plaintext to the operator exactly once.
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

/// Compute the SHA-256 hex digest of a token's plaintext.
///
/// This is the only representation of a token that is ever persisted.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Validate the structural format of a token before doing any database work.
///
/// Rejects anything that is not `mf_enroll_<non-empty alphanumeric/underscore>`
/// or that exceeds [`MAX_TOKEN_LEN`]. Returns `true` when the format is
/// acceptable. The token value is never logged here.
pub fn is_well_formed(token: &str) -> bool {
    if token.len() > MAX_TOKEN_LEN {
        return false;
    }
    let Some(suffix) = token.strip_prefix(TOKEN_PREFIX) else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Constant-time equality for two byte slices.
///
/// The comparison time depends only on the (public) length, not on where the
/// first differing byte is, so it cannot be used as a timing oracle. Used to
/// compare token hashes.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_well_formed_and_unique() {
        let a = generate_token();
        let b = generate_token();
        assert!(a.starts_with(TOKEN_PREFIX));
        assert!(is_well_formed(&a));
        assert_ne!(a, b, "tokens must not collide");
        // 256 bits of entropy => 64 hex chars after the prefix.
        assert_eq!(a.len(), TOKEN_PREFIX.len() + TOKEN_ENTROPY_BYTES * 2);
    }

    #[test]
    fn hash_is_stable_and_sha256_sized() {
        let token = "mf_enroll_deadbeef";
        let first = hash_token(token);
        let second = hash_token(token);
        assert_eq!(first, second);
        // SHA-256 hex digest is 64 characters.
        assert_eq!(first.len(), 64);
        // Distinct tokens produce distinct hashes.
        assert_ne!(hash_token("mf_enroll_aaaa"), hash_token("mf_enroll_bbbb"));
    }

    #[test]
    fn known_sha256_vector() {
        // SHA-256("abc") — a published test vector.
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn well_formed_accepts_valid_and_rejects_invalid() {
        assert!(is_well_formed("mf_enroll_abcDEF123_456"));
        for bad in [
            "",
            "mf_enroll_",          // empty suffix
            "enroll_abc",          // wrong prefix
            "mf_enroll_has space", // space
            "mf_enroll_semi;colon",
            "MF_ENROLL_abc", // case-sensitive prefix
        ] {
            assert!(!is_well_formed(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
