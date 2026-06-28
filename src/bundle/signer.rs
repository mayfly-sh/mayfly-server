//! The Bundle Signing Key and signature verification.
//!
//! The Bundle Signing Key is a **dedicated** Ed25519 keypair used only to sign
//! bundle metadata. It is deliberately *not* one of the SSH CA keys: SSH CA
//! keys sign user certificates, the Bundle Signing Key signs the trust bundle
//! that lists those CA keys. Separating them means a compromise of the bundle
//! channel does not yield a certificate-signing key, and the bundle key can be
//! rotated independently.
//!
//! [`BundleSigner`] is a trait so production can hold a real key while tests
//! inject a deterministic one. Verification ([`verify_signed_bundle`]) is a
//! free function that fails closed on every error path and verifies the
//! signature against a **pinned** key the agent obtained out of band (at
//! enrollment), never merely the key embedded in the bundle.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SIGNATURE_LENGTH};

use crate::bundle::canonical::{canonical_message, CanonicalInput};
use crate::bundle::models::{BundleError, SignedBundle, BUNDLE_VERSION, SIGNATURE_ALGORITHM};

/// Length of an Ed25519 seed / public key in bytes.
const KEY_LEN: usize = 32;

/// Something that can sign bundle canonical bytes with the Bundle Signing Key.
pub trait BundleSigner: Send + Sync {
    /// Sign `message`, returning the raw 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH];

    /// The 32-byte Ed25519 public key of this signer.
    fn public_key_bytes(&self) -> [u8; KEY_LEN];

    /// The signature algorithm identifier (`ed25519`).
    fn algorithm(&self) -> &'static str {
        SIGNATURE_ALGORITHM
    }

    /// Base64 of [`Self::public_key_bytes`].
    fn public_key_b64(&self) -> String {
        BASE64.encode(self.public_key_bytes())
    }

    /// Base64 signature of `message`.
    fn sign_b64(&self, message: &[u8]) -> String {
        BASE64.encode(self.sign(message))
    }
}

/// The production Ed25519 Bundle Signing Key.
///
/// Never derives `Debug`/`Clone`/serialization that could expose the seed.
pub struct Ed25519BundleSigner {
    signing_key: SigningKey,
}

impl Ed25519BundleSigner {
    /// Build from a raw 32-byte seed.
    pub fn from_seed(seed: &[u8; KEY_LEN]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        use ssh_key::rand_core::{OsRng, RngCore};
        let mut seed = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut seed);
        let signer = Self::from_seed(&seed);
        // Best-effort scrub of the local seed copy.
        seed.iter_mut().for_each(|b| *b = 0);
        signer
    }

    /// The base64-encoded 32-byte seed, for persistence. Sensitive.
    fn seed_b64(&self) -> String {
        BASE64.encode(self.signing_key.to_bytes())
    }

    /// Load the Bundle Signing Key, preferring (in order):
    ///
    /// 1. the environment variable `env_var` holding a base64 32-byte seed;
    /// 2. an existing `<storage_dir>/bundle_signing.seed` file;
    /// 3. a freshly generated key, persisted to that file with `0600`
    ///    permissions so it is stable across restarts.
    ///
    /// This mirrors the CA storage model: an operator may pin the key via the
    /// environment (e.g. from a secrets manager), otherwise the server manages
    /// it on disk alongside the encrypted CA material.
    pub fn load_or_create(env_var: &str, storage_dir: &Path) -> Result<Self, BundleError> {
        if let Ok(value) = std::env::var(env_var) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Self::from_seed_b64(trimmed);
            }
        }

        let path = storage_dir.join("bundle_signing.seed");
        if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| BundleError::Crypto(format!("read bundle signing key: {e}")))?;
            return Self::from_seed_b64(contents.trim());
        }

        // Generate and persist a new key.
        let signer = Self::generate();
        std::fs::create_dir_all(storage_dir)
            .map_err(|e| BundleError::Crypto(format!("create storage dir: {e}")))?;
        std::fs::write(&path, signer.seed_b64().as_bytes())
            .map_err(|e| BundleError::Crypto(format!("write bundle signing key: {e}")))?;
        restrict_permissions(&path);
        Ok(signer)
    }

    /// Decode a base64 32-byte seed.
    fn from_seed_b64(value: &str) -> Result<Self, BundleError> {
        let raw = BASE64
            .decode(value.as_bytes())
            .map_err(|_| BundleError::Malformed("bundle signing seed is not base64".to_string()))?;
        let seed: [u8; KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| BundleError::Malformed("bundle signing seed must be 32 bytes".to_string()))?;
        Ok(Self::from_seed(&seed))
    }
}

impl BundleSigner for Ed25519BundleSigner {
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }

    fn public_key_bytes(&self) -> [u8; KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }
}

/// Verify a [`SignedBundle`] against a **pinned** signing key and a current
/// time. Fails closed on every error.
///
/// Verification order is deliberate:
/// 1. schema version is supported (reject unknown → no downgrade);
/// 2. signature algorithm is supported;
/// 3. the embedded signing key matches the pinned key (reject signer swap);
/// 4. the signature verifies over the *canonical* bytes (authenticity);
/// 5. only then is freshness (`expires_at`) checked.
///
/// Authenticity is established before freshness so an attacker cannot influence
/// control flow with unauthenticated timestamp fields.
pub fn verify_signed_bundle(
    bundle: &SignedBundle,
    pinned_signing_key: &[u8; KEY_LEN],
    now: DateTime<Utc>,
) -> Result<(), BundleError> {
    if bundle.bundle_version != BUNDLE_VERSION {
        return Err(BundleError::UnsupportedVersion(bundle.bundle_version.clone()));
    }
    if bundle.signature_algorithm != SIGNATURE_ALGORITHM {
        return Err(BundleError::UnsupportedAlgorithm(
            bundle.signature_algorithm.clone(),
        ));
    }

    // The bundle advertises its signer; require it to be the pinned key so a
    // swapped-key bundle is rejected before any signature math.
    let embedded = BASE64
        .decode(bundle.signing_public_key.as_bytes())
        .map_err(|_| BundleError::Malformed("signing_public_key is not base64".to_string()))?;
    if embedded.as_slice() != pinned_signing_key.as_slice() {
        return Err(BundleError::UntrustedSigner);
    }

    let verifying = VerifyingKey::from_bytes(pinned_signing_key)
        .map_err(|_| BundleError::Malformed("pinned signing key is invalid".to_string()))?;

    let sig_raw = BASE64
        .decode(bundle.signature.as_bytes())
        .map_err(|_| BundleError::Malformed("signature is not base64".to_string()))?;
    let sig_bytes: [u8; SIGNATURE_LENGTH] = sig_raw
        .as_slice()
        .try_into()
        .map_err(|_| BundleError::Malformed("signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let message = canonical_message(&CanonicalInput {
        bundle_version: &bundle.bundle_version,
        generation: bundle.generation,
        created_at: &bundle.created_at,
        expires_at: &bundle.expires_at,
        fingerprint: &bundle.fingerprint,
        algorithm: &bundle.signature_algorithm,
        keys: &bundle.keys,
    })?;

    verifying
        .verify_strict(&message, &signature)
        .map_err(|_| BundleError::SignatureInvalid)?;

    // Authenticated: now enforce freshness.
    let expires = DateTime::parse_from_rfc3339(&bundle.expires_at)
        .map_err(|_| BundleError::Malformed("expires_at is not RFC 3339".to_string()))?
        .with_timezone(&Utc);
    if now > expires {
        return Err(BundleError::Expired);
    }
    Ok(())
}

/// Best-effort restriction of the seed file to owner-only read/write (`0600`).
#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::models::{BundleKey, SIGNATURE_ALGORITHM};

    fn signer() -> Ed25519BundleSigner {
        Ed25519BundleSigner::from_seed(&[7u8; 32])
    }

    fn signed_bundle(s: &dyn BundleSigner, now: DateTime<Utc>) -> SignedBundle {
        let keys = vec![BundleKey {
            key_id: "ca-01".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            fingerprint: "SHA256:x".to_string(),
        }];
        let created_at = now.to_rfc3339();
        let expires_at = (now + chrono::Duration::hours(1)).to_rfc3339();
        let fingerprint = "sha256:deadbeef".to_string();
        let message = canonical_message(&CanonicalInput {
            bundle_version: BUNDLE_VERSION,
            generation: 5,
            created_at: &created_at,
            expires_at: &expires_at,
            fingerprint: &fingerprint,
            algorithm: SIGNATURE_ALGORITHM,
            keys: &keys,
        })
        .unwrap();
        SignedBundle {
            bundle_version: BUNDLE_VERSION.to_string(),
            generation: 5,
            created_at,
            expires_at,
            fingerprint,
            keys,
            signature_algorithm: SIGNATURE_ALGORITHM.to_string(),
            signature: s.sign_b64(&message),
            signing_public_key: s.public_key_b64(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-29T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn round_trip_verifies() {
        let s = signer();
        let bundle = signed_bundle(&s, now());
        assert!(verify_signed_bundle(&bundle, &s.public_key_bytes(), now()).is_ok());
    }

    #[test]
    fn tampered_generation_fails() {
        let s = signer();
        let mut bundle = signed_bundle(&s, now());
        bundle.generation = 6;
        assert!(matches!(
            verify_signed_bundle(&bundle, &s.public_key_bytes(), now()),
            Err(BundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_key_list_fails() {
        let s = signer();
        let mut bundle = signed_bundle(&s, now());
        bundle.keys[0].public_key = "ssh-ed25519 EVIL".to_string();
        assert!(matches!(
            verify_signed_bundle(&bundle, &s.public_key_bytes(), now()),
            Err(BundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_pinned_key_is_untrusted() {
        let s = signer();
        let bundle = signed_bundle(&s, now());
        let other = Ed25519BundleSigner::from_seed(&[9u8; 32]);
        assert!(matches!(
            verify_signed_bundle(&bundle, &other.public_key_bytes(), now()),
            Err(BundleError::UntrustedSigner)
        ));
    }

    #[test]
    fn forged_bundle_under_attacker_key_fails() {
        // Attacker re-signs a tampered bundle with their own key and rewrites
        // the embedded signing key. Pinning rejects it.
        let attacker = Ed25519BundleSigner::from_seed(&[1u8; 32]);
        let honest = signer();
        let mut bundle = signed_bundle(&attacker, now());
        bundle.signing_public_key = attacker.public_key_b64();
        assert!(matches!(
            verify_signed_bundle(&bundle, &honest.public_key_bytes(), now()),
            Err(BundleError::UntrustedSigner)
        ));
    }

    #[test]
    fn expired_bundle_fails_after_signature() {
        let s = signer();
        let bundle = signed_bundle(&s, now());
        let later = now() + chrono::Duration::hours(2);
        assert!(matches!(
            verify_signed_bundle(&bundle, &s.public_key_bytes(), later),
            Err(BundleError::Expired)
        ));
    }

    #[test]
    fn unsupported_version_rejected() {
        let s = signer();
        let mut bundle = signed_bundle(&s, now());
        bundle.bundle_version = "v2".to_string();
        assert!(matches!(
            verify_signed_bundle(&bundle, &s.public_key_bytes(), now()),
            Err(BundleError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn malformed_signature_rejected() {
        let s = signer();
        let mut bundle = signed_bundle(&s, now());
        bundle.signature = "not-base64-!!!".to_string();
        assert!(matches!(
            verify_signed_bundle(&bundle, &s.public_key_bytes(), now()),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn seed_b64_round_trips() {
        let s = Ed25519BundleSigner::from_seed(&[3u8; 32]);
        let restored = Ed25519BundleSigner::from_seed_b64(&s.seed_b64()).unwrap();
        assert_eq!(restored.public_key_bytes(), s.public_key_bytes());
    }
}
