//! Input validation for enrollment requests.
//!
//! These checks run before any database work and mirror the agent's own
//! client-side validation, so a well-behaved agent and the server agree on what
//! a valid hostname and public key look like. The server never trusts the
//! client to have validated anything.

use ssh_key::{Algorithm, PublicKey};

/// Maximum total hostname length (RFC 1035 / 1123).
const MAX_HOSTNAME_LEN: usize = 253;

/// Maximum length of a single dot-separated label.
const MAX_LABEL_LEN: usize = 63;

/// Validate a hostname against a conservative subset of RFC 1123.
///
/// Each dot-separated label must be non-empty, at most 63 characters, contain
/// only ASCII alphanumerics and hyphens, and not start or end with a hyphen.
pub fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_LEN {
        return false;
    }
    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Validate that `public_key` parses as an OpenSSH **Ed25519** public key.
///
/// Returns the normalized OpenSSH encoding on success. Any other algorithm
/// (RSA, ECDSA, …) or unparseable input is rejected.
pub fn validate_ed25519_public_key(public_key: &str) -> Result<String, PublicKeyError> {
    let key = PublicKey::from_openssh(public_key).map_err(|_| PublicKeyError::Malformed)?;
    if !matches!(key.algorithm(), Algorithm::Ed25519) {
        return Err(PublicKeyError::NotEd25519);
    }
    key.to_openssh().map_err(|_| PublicKeyError::Malformed)
}

/// The SHA-256 fingerprint (`SHA256:…`) of an OpenSSH public key, for auditing.
///
/// Returns `None` if the key cannot be parsed; callers that have already run
/// [`validate_ed25519_public_key`] can treat `None` as unreachable.
pub fn public_key_fingerprint(public_key: &str) -> Option<String> {
    PublicKey::from_openssh(public_key)
        .ok()
        .map(|key| key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

/// Why a public key was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyError {
    /// The key could not be parsed as an OpenSSH public key.
    Malformed,
    /// The key parsed but is not an Ed25519 key.
    NotEd25519,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::PrivateKey;

    fn ed25519_public_key() -> String {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("gen")
            .public_key()
            .to_openssh()
            .expect("openssh")
    }

    #[test]
    fn accepts_reasonable_hostnames() {
        for good in ["web-01", "a", "host.example.com", "db1.internal", "x.y.z"] {
            assert!(is_valid_hostname(good), "{good:?} should be valid");
        }
    }

    #[test]
    fn rejects_bad_hostnames() {
        for bad in [
            "",
            "-leading",
            "trailing-",
            "has space",
            "under_score",
            "double..dot",
            "UPPER_is_fine_but_underscore_not", // underscore rejected
        ] {
            assert!(!is_valid_hostname(bad), "{bad:?} should be rejected");
        }
        // Over-length hostname.
        let long = "a".repeat(254);
        assert!(!is_valid_hostname(&long));
        // Over-length label.
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(!is_valid_hostname(&long_label));
    }

    #[test]
    fn accepts_ed25519_public_key() {
        let key = ed25519_public_key();
        let normalized = validate_ed25519_public_key(&key).expect("valid");
        assert!(normalized.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn rejects_malformed_public_key() {
        assert_eq!(
            validate_ed25519_public_key("not a key"),
            Err(PublicKeyError::Malformed)
        );
    }

    #[test]
    fn rejects_non_ed25519_public_key() {
        // A P-256 key must be rejected (dev-only feature in tests).
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .expect("gen p256")
        .public_key()
        .to_openssh()
        .expect("openssh");
        assert_eq!(
            validate_ed25519_public_key(&key),
            Err(PublicKeyError::NotEd25519)
        );
    }

    #[test]
    fn fingerprint_is_sha256_prefixed() {
        let key = ed25519_public_key();
        let fingerprint = public_key_fingerprint(&key).expect("fingerprint");
        assert!(fingerprint.starts_with("SHA256:"));
    }
}
