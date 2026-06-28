//! Domain types, validation, and the canonical fingerprint for the CA bundle.
//!
//! The **fingerprint is computed over canonical JSON**, never over the rendered
//! `TrustedUserCAKeys` text file. Canonical JSON here is a manually constructed,
//! byte-for-byte stable encoding (sorted keys, fixed field order, explicit
//! escaping) so that the server and the agent — two independent crates — produce
//! identical bytes and therefore identical fingerprints. See [`canonical_json`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, PublicKey};

/// Minimum number of keys a distributable bundle may contain.
pub const MIN_CA_KEYS: usize = 1;
/// Maximum number of keys a bundle may contain.
pub const MAX_CA_KEYS: usize = 64;
/// Maximum accepted `key_id` length.
pub const MAX_KEY_ID_LEN: usize = 64;
/// Maximum accepted public-key line length.
pub const MAX_PUBLIC_KEY_LEN: usize = 4096;

/// A CA key as stored on the server (the full record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaKeyRecord {
    /// Stable, operator-assigned identifier (e.g. `ca-01`).
    pub key_id: String,
    /// OpenSSH Ed25519 public key line.
    pub public_key: String,
    /// When the key was added (RFC 3339).
    pub created_at: String,
    /// Bundle generation at which the key was added (informational).
    pub generation: i64,
    /// Whether the key is currently distributed.
    pub enabled: bool,
}

/// Maximum accepted fingerprint length on an acknowledgement.
pub const MAX_FINGERPRINT_LEN: usize = 128;

/// Request body for `POST /api/v1/agent/ca-bundle/ack`.
#[derive(Debug, Clone, Deserialize)]
pub struct AckRequest {
    /// The generation the agent applied.
    pub generation: i64,
    /// The fingerprint the agent confirmed.
    pub fingerprint: String,
    /// Outcome of the sync; must be `"success"`.
    pub status: String,
}

/// Response body for a recorded acknowledgement.
#[derive(Debug, Clone, Serialize)]
pub struct AckResponse {
    /// Always `"recorded"` on success.
    pub status: &'static str,
    /// The generation now recorded as synced for this machine.
    pub generation: i64,
}

/// Why an acknowledgement was rejected.
#[derive(Debug, thiserror::Error)]
pub enum AckError {
    /// The body failed validation (e.g. non-`success` status, blank fingerprint).
    #[error("{0}")]
    Invalid(String),
    /// The acknowledged generation/fingerprint does not match the current bundle.
    #[error("acknowledged generation or fingerprint does not match the current bundle")]
    Mismatch,
    /// The authenticated machine no longer exists.
    #[error("machine not found")]
    UnknownMachine,
    /// Assembling the current bundle for comparison failed.
    #[error(transparent)]
    Bundle(#[from] CaBundleError),
}

impl From<AckError> for crate::errors::ApiError {
    fn from(err: AckError) -> Self {
        match err {
            AckError::Invalid(msg) => Self::BadRequest(msg),
            AckError::Mismatch => Self::Conflict(
                "acknowledged generation or fingerprint does not match the current bundle"
                    .to_string(),
            ),
            // Authenticated but the machine vanished: fail closed as auth failure.
            AckError::UnknownMachine => {
                Self::Unauthorized("request authentication failed".to_string())
            }
            AckError::Bundle(err) => err.into(),
        }
    }
}

/// One entry in a distributed bundle: only the public material is exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaBundleKey {
    /// Stable key identifier.
    pub key_id: String,
    /// OpenSSH Ed25519 public key line.
    pub public_key: String,
}

/// A validated, serializable CA bundle. This is the exact response body of
/// `GET /api/v1/agent/ca-bundle`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaBundle {
    /// Monotonic bundle generation.
    pub generation: i64,
    /// `sha256:<hex>` over the canonical JSON of `{generation, keys}`.
    pub fingerprint: String,
    /// Distributed keys, sorted by `key_id` for determinism.
    pub keys: Vec<CaBundleKey>,
}

/// Why a bundle is invalid. Validation runs over server-owned data, so these
/// generally indicate a server-side misconfiguration rather than a client fault.
#[derive(Debug, thiserror::Error)]
pub enum CaBundleError {
    /// Fewer than [`MIN_CA_KEYS`] keys.
    #[error("bundle must contain at least one key")]
    Empty,
    /// More than [`MAX_CA_KEYS`] keys.
    #[error("bundle exceeds the maximum of {MAX_CA_KEYS} keys")]
    TooManyKeys,
    /// Two keys share a `key_id`.
    #[error("bundle contains a duplicate key_id")]
    DuplicateKeyId,
    /// Two keys share a public key.
    #[error("bundle contains a duplicate public_key")]
    DuplicatePublicKey,
    /// A `key_id` is empty, too long, or contains illegal characters.
    #[error("bundle contains an invalid key_id")]
    InvalidKeyId,
    /// A public key is unparseable or not Ed25519.
    #[error("bundle contains an invalid CA public key")]
    InvalidPublicKey,
    /// The generation is not a positive integer.
    #[error("bundle generation is invalid")]
    InvalidGeneration,
    /// A database operation failed while assembling the bundle.
    #[error("CA bundle database error")]
    Database(#[from] sqlx::Error),
}

impl From<CaBundleError> for crate::errors::ApiError {
    fn from(err: CaBundleError) -> Self {
        // Every variant reflects server-side state (bad stored data or a DB
        // failure), never client input on this path, so it is an internal error.
        Self::internal(anyhow::Error::new(err))
    }
}

impl CaBundle {
    /// Validate `keys` and `generation`, sort keys deterministically, compute
    /// the canonical fingerprint, and assemble the bundle.
    pub fn build(generation: i64, mut keys: Vec<CaBundleKey>) -> Result<Self, CaBundleError> {
        if generation < 1 {
            return Err(CaBundleError::InvalidGeneration);
        }
        if keys.len() < MIN_CA_KEYS {
            return Err(CaBundleError::Empty);
        }
        if keys.len() > MAX_CA_KEYS {
            return Err(CaBundleError::TooManyKeys);
        }

        // Deterministic ordering: by key_id (unique), then public_key.
        keys.sort_by(|a, b| {
            a.key_id
                .cmp(&b.key_id)
                .then_with(|| a.public_key.cmp(&b.public_key))
        });

        for (index, key) in keys.iter().enumerate() {
            validate_key_id(&key.key_id)?;
            validate_ca_public_key(&key.public_key)?;
            if index > 0 {
                let prev = &keys[index - 1];
                if prev.key_id == key.key_id {
                    return Err(CaBundleError::DuplicateKeyId);
                }
            }
        }

        // Duplicate public keys need a separate pass since the sort key is the
        // key_id; collect and compare sorted public keys.
        let mut public_keys: Vec<&str> = keys.iter().map(|k| k.public_key.as_str()).collect();
        public_keys.sort_unstable();
        for window in public_keys.windows(2) {
            if window[0] == window[1] {
                return Err(CaBundleError::DuplicatePublicKey);
            }
        }

        let fingerprint = compute_fingerprint(generation, &keys);
        Ok(Self {
            generation,
            fingerprint,
            keys,
        })
    }
}

/// Validate a `key_id`: non-empty, bounded, printable ASCII without whitespace
/// or control characters.
fn validate_key_id(key_id: &str) -> Result<(), CaBundleError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        return Err(CaBundleError::InvalidKeyId);
    }
    let ok = key_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    if ok {
        Ok(())
    } else {
        Err(CaBundleError::InvalidKeyId)
    }
}

/// Validate a CA public key: a parseable OpenSSH key that is Ed25519.
fn validate_ca_public_key(public_key: &str) -> Result<(), CaBundleError> {
    if public_key.is_empty()
        || public_key.len() > MAX_PUBLIC_KEY_LEN
        || public_key.chars().any(|c| c.is_control())
    {
        return Err(CaBundleError::InvalidPublicKey);
    }
    let key = PublicKey::from_openssh(public_key).map_err(|_| CaBundleError::InvalidPublicKey)?;
    if matches!(key.algorithm(), Algorithm::Ed25519) {
        Ok(())
    } else {
        Err(CaBundleError::InvalidPublicKey)
    }
}

/// Build the canonical JSON for a bundle: `{"generation":N,"keys":[...]}` where
/// the keys array is in the given (already-sorted) order and every string is
/// explicitly escaped. This must stay byte-for-byte identical to the agent's
/// implementation.
pub fn canonical_json(generation: i64, keys: &[CaBundleKey]) -> String {
    let mut out = String::with_capacity(64 + keys.len() * 96);
    out.push_str("{\"generation\":");
    out.push_str(&generation.to_string());
    out.push_str(",\"keys\":[");
    for (index, key) in keys.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"key_id\":");
        json_escape_into(&key.key_id, &mut out);
        out.push_str(",\"public_key\":");
        json_escape_into(&key.public_key, &mut out);
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// Compute the `sha256:<hex>` fingerprint over the canonical JSON.
pub fn compute_fingerprint(generation: i64, keys: &[CaBundleKey]) -> String {
    let canonical = canonical_json(generation, keys);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// Append a JSON string literal (quoted and escaped) for `value` to `out`.
///
/// Deliberately hand-rolled (rather than `serde_json`) so the exact escaping is
/// pinned and trivially mirrored by the agent.
fn json_escape_into(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Deterministic OpenSSH Ed25519 public key from a 32-byte seed.
    fn openssh_public(seed: u8) -> String {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let verifying = signing.verifying_key();
        let key_data = ssh_key::public::Ed25519PublicKey(verifying.to_bytes());
        ssh_key::PublicKey::from(ssh_key::public::KeyData::Ed25519(key_data))
            .to_openssh()
            .expect("openssh")
    }

    fn key(id: &str, seed: u8) -> CaBundleKey {
        CaBundleKey {
            key_id: id.to_string(),
            public_key: openssh_public(seed),
        }
    }

    #[test]
    fn canonical_json_is_sorted_and_stable() {
        let a = vec![key("ca-02", 2), key("ca-01", 1)];
        let bundle = CaBundle::build(7, a).expect("build");
        // Keys are sorted by key_id in the canonical output.
        let canonical = canonical_json(bundle.generation, &bundle.keys);
        let idx1 = canonical.find("ca-01").unwrap();
        let idx2 = canonical.find("ca-02").unwrap();
        assert!(idx1 < idx2);
        assert!(canonical.starts_with("{\"generation\":7,\"keys\":[{\"key_id\":\"ca-01\""));
    }

    #[test]
    fn fingerprint_is_independent_of_input_order() {
        let forward = CaBundle::build(3, vec![key("ca-01", 1), key("ca-02", 2)]).unwrap();
        let reverse = CaBundle::build(3, vec![key("ca-02", 2), key("ca-01", 1)]).unwrap();
        assert_eq!(forward.fingerprint, reverse.fingerprint);
        assert!(forward.fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn fingerprint_changes_with_generation_and_keys() {
        let base = CaBundle::build(1, vec![key("ca-01", 1)]).unwrap();
        let gen2 = CaBundle::build(2, vec![key("ca-01", 1)]).unwrap();
        let other = CaBundle::build(1, vec![key("ca-01", 9)]).unwrap();
        assert_ne!(base.fingerprint, gen2.fingerprint);
        assert_ne!(base.fingerprint, other.fingerprint);
    }

    #[test]
    fn canonical_json_known_vector() {
        // A fixed key_id with a fixed key gives a stable canonical string; this
        // is the cross-crate contract the agent mirrors.
        let keys = vec![CaBundleKey {
            key_id: "ca-01".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
        }];
        assert_eq!(
            canonical_json(42, &keys),
            "{\"generation\":42,\"keys\":[{\"key_id\":\"ca-01\",\"public_key\":\"ssh-ed25519 AAAA\"}]}"
        );
    }

    #[test]
    fn rejects_empty_bundle() {
        assert!(matches!(
            CaBundle::build(1, vec![]).unwrap_err(),
            CaBundleError::Empty
        ));
    }

    #[test]
    fn rejects_too_many_keys() {
        let keys: Vec<CaBundleKey> = (0..=MAX_CA_KEYS as u8)
            .map(|i| key(&format!("ca-{i:03}"), i))
            .collect();
        assert!(matches!(
            CaBundle::build(1, keys).unwrap_err(),
            CaBundleError::TooManyKeys
        ));
    }

    #[test]
    fn rejects_duplicate_key_id() {
        let keys = vec![key("ca-01", 1), key("ca-01", 2)];
        assert!(matches!(
            CaBundle::build(1, keys).unwrap_err(),
            CaBundleError::DuplicateKeyId
        ));
    }

    #[test]
    fn rejects_duplicate_public_key() {
        let keys = vec![key("ca-01", 5), key("ca-02", 5)];
        assert!(matches!(
            CaBundle::build(1, keys).unwrap_err(),
            CaBundleError::DuplicatePublicKey
        ));
    }

    #[test]
    fn rejects_invalid_generation() {
        assert!(matches!(
            CaBundle::build(0, vec![key("ca-01", 1)]).unwrap_err(),
            CaBundleError::InvalidGeneration
        ));
    }

    #[test]
    fn rejects_invalid_public_key() {
        let bad = vec![CaBundleKey {
            key_id: "ca-01".to_string(),
            public_key: "not a key".to_string(),
        }];
        assert!(matches!(
            CaBundle::build(1, bad).unwrap_err(),
            CaBundleError::InvalidPublicKey
        ));
    }

    #[test]
    fn rejects_non_ed25519_public_key() {
        let rsa = vec![CaBundleKey {
            key_id: "ca-01".to_string(),
            public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDExample test".to_string(),
        }];
        assert!(matches!(
            CaBundle::build(1, rsa).unwrap_err(),
            CaBundleError::InvalidPublicKey
        ));
    }

    #[test]
    fn rejects_invalid_key_id() {
        let bad = vec![CaBundleKey {
            key_id: "has space".to_string(),
            public_key: openssh_public(1),
        }];
        assert!(matches!(
            CaBundle::build(1, bad).unwrap_err(),
            CaBundleError::InvalidKeyId
        ));
    }

    #[test]
    fn json_escape_handles_specials() {
        let mut out = String::new();
        json_escape_into("a\"b\\c\n", &mut out);
        assert_eq!(out, "\"a\\\"b\\\\c\\n\"");
    }
}
