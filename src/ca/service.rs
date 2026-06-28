//! A single in-memory CA signing key.
//!
//! [`CaKey`] owns one decrypted Ed25519 private key and the public material
//! derived from it. It signs and verifies OpenSSH user certificates entirely
//! with the `ssh-key` crate — no `ssh-keygen`, no shell execution, ever. The
//! private key is held only in memory (`ssh-key`'s `PrivateKey` zeroizes its
//! secret material on drop) and is never printed by `Debug`.
//!
//! [`CaKey`] is a *pure signer*: it has no lifecycle state (enabled/disabled,
//! timestamps, usage counters). That mutable metadata lives in
//! [`crate::ca::CaRecord`], owned by the [`crate::ca::CaManager`]. The
//! certificate `key_id` is passed in at sign time so a renamed CA signs with
//! its current id without rebuilding the signer.

use chrono::{DateTime, SecondsFormat, Utc};
use ssh_key::certificate::{Builder, CertType, Certificate};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Fingerprint, HashAlg, LineEnding, PrivateKey, PublicKey};

use crate::ca::errors::CaError;
use crate::ca::models::{
    CertificateRequest, CertificateResponse, DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS, MIN_TTL_SECONDS,
};

/// Non-critical extensions granted on every issued user certificate.
pub(crate) const STANDARD_EXTENSIONS: [&str; 3] = [
    "permit-pty",
    "permit-port-forwarding",
    "permit-agent-forwarding",
];

/// A single CA signing key.
///
/// Deliberately does not derive `Debug`: it owns decrypted key material.
pub struct CaKey {
    /// Decrypted Ed25519 private key. Never logged, never `Debug`-printed.
    private_key: PrivateKey,
    /// OpenSSH-encoded public key (cached, non-secret).
    public_key: String,
    /// SHA-256 fingerprint string `SHA256:...` (cached, non-secret).
    fingerprint: String,
}

impl std::fmt::Debug for CaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("CaKey")
            .field("fingerprint", &self.fingerprint)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl CaKey {
    /// Wrap an already-decrypted private key as a signer.
    ///
    /// Fails if the key is not Ed25519 or its public key cannot be encoded.
    /// The `key_id` is used only for error context.
    pub fn from_private_key(private_key: PrivateKey, key_id: &str) -> Result<Self, CaError> {
        if !matches!(private_key.algorithm(), Algorithm::Ed25519) {
            return Err(CaError::NotEd25519 {
                key_id: key_id.to_string(),
                algorithm: private_key.algorithm().as_str().to_string(),
            });
        }
        let public_key = private_key
            .public_key()
            .to_openssh()
            .map_err(|err| CaError::Encode(err.to_string()))?;
        let fingerprint = private_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        Ok(Self {
            private_key,
            public_key,
            fingerprint,
        })
    }

    /// Decrypt an OpenSSH private key with `passphrase` and wrap it as a signer.
    ///
    /// Reports the offending `key_id` on parse/decrypt/algorithm failures.
    pub fn from_encrypted_openssh(
        encrypted: &str,
        passphrase: &str,
        key_id: &str,
    ) -> Result<Self, CaError> {
        let key = PrivateKey::from_openssh(encrypted).map_err(|err| CaError::Parse {
            key_id: key_id.to_string(),
            message: err.to_string(),
        })?;
        let decrypted = if key.is_encrypted() {
            key.decrypt(passphrase).map_err(|_| CaError::Decrypt {
                key_id: key_id.to_string(),
            })?
        } else {
            key
        };
        Self::from_private_key(decrypted, key_id)
    }

    /// Encrypt this key to an OpenSSH-armored string for storage at rest.
    pub fn to_encrypted_openssh(&self, passphrase: &str, key_id: &str) -> Result<String, CaError> {
        let encrypted =
            self.private_key
                .encrypt(&mut OsRng, passphrase)
                .map_err(|err| CaError::Sign(format!("failed to encrypt ca key '{key_id}': {err}")))?;
        encrypted
            .to_openssh(LineEnding::LF)
            .map(|z| z.to_string())
            .map_err(|err| CaError::Encode(err.to_string()))
    }

    /// The CA public key in OpenSSH format.
    pub fn public_openssh(&self) -> &str {
        &self.public_key
    }

    /// The SHA-256 fingerprint string (`SHA256:...`).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The `ssh-key` fingerprint used for cryptographic issuer verification.
    fn ssh_fingerprint(&self) -> Fingerprint {
        self.private_key.public_key().fingerprint(HashAlg::Sha256)
    }

    /// Whether `certificate` was actually signed by this key.
    ///
    /// Verifies the cryptographic signature (via `validate_at` at the
    /// certificate's own `valid_after`), not merely a fingerprint claim.
    pub fn signed(&self, certificate: &Certificate) -> bool {
        let fingerprint = self.ssh_fingerprint();
        certificate
            .validate_at(certificate.valid_after(), [&fingerprint])
            .is_ok()
    }

    /// Issue and sign an SSH user certificate for `request`, anchoring validity
    /// and the serial to `now` (unix epoch seconds). `key_id` is embedded in
    /// the certificate and returned as `ca_key_id`.
    pub fn sign_certificate(
        &self,
        request: &CertificateRequest,
        now: i64,
        key_id: &str,
    ) -> Result<CertificateResponse, CaError> {
        let ttl = validate_ttl(request.ttl_seconds)?;

        let principal = request.github_login.trim();
        if principal.is_empty() {
            return Err(CaError::InvalidRequest(
                "github_login must not be empty".to_string(),
            ));
        }
        let hostname = request.hostname.trim();
        if hostname.is_empty() {
            return Err(CaError::InvalidRequest(
                "hostname must not be empty".to_string(),
            ));
        }

        let subject = PublicKey::from_openssh(&request.public_key)
            .map_err(|err| CaError::InvalidRequest(format!("invalid public_key: {err}")))?;
        let fingerprint = subject.fingerprint(HashAlg::Sha256).to_string();

        let valid_after = u64::try_from(now)
            .map_err(|_| CaError::Sign("clock is before the unix epoch".to_string()))?;
        let serial = valid_after;
        let valid_before = valid_after + u64::from(ttl);

        let mut builder =
            Builder::new_with_random_nonce(&mut OsRng, subject, valid_after, valid_before)
                .map_err(sign_err)?;
        builder.serial(serial).map_err(sign_err)?;
        builder.key_id(key_id).map_err(sign_err)?;
        builder.cert_type(CertType::User).map_err(sign_err)?;
        builder.valid_principal(principal).map_err(sign_err)?;
        builder
            .comment(format!("{principal}@{hostname}"))
            .map_err(sign_err)?;
        for extension in STANDARD_EXTENSIONS {
            builder.extension(extension, "").map_err(sign_err)?;
        }

        let certificate = builder.sign(&self.private_key).map_err(sign_err)?;
        let openssh = certificate
            .to_openssh()
            .map_err(|err| CaError::Encode(err.to_string()))?;

        Ok(CertificateResponse {
            certificate: openssh,
            serial,
            valid_after: format_timestamp(valid_after),
            valid_before: format_timestamp(valid_before),
            ttl_seconds: ttl,
            principal: principal.to_string(),
            fingerprint,
            ca_key_id: key_id.to_string(),
            ca_fingerprint: self.fingerprint.clone(),
        })
    }
}

fn sign_err(err: ssh_key::Error) -> CaError {
    CaError::Sign(err.to_string())
}

fn validate_ttl(requested: u32) -> Result<u32, CaError> {
    let ttl = if requested == 0 {
        DEFAULT_TTL_SECONDS
    } else {
        requested
    };
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl) {
        return Err(CaError::InvalidRequest(format!(
            "ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}, got {requested}"
        )));
    }
    Ok(ttl)
}

/// Format a unix timestamp as RFC 3339 with second precision.
pub(crate) fn format_timestamp(seconds: u64) -> String {
    DateTime::<Utc>::from_timestamp(seconds as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::EcdsaCurve;

    fn now() -> i64 {
        DateTime::parse_from_rfc3339("2026-06-24T12:00:00Z")
            .unwrap()
            .timestamp()
    }

    fn ed25519_signer(key_id: &str) -> CaKey {
        let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen");
        CaKey::from_private_key(private, key_id).expect("build")
    }

    fn user_public_key() -> String {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("gen")
            .public_key()
            .to_openssh()
            .expect("openssh")
    }

    fn request(ttl: u32) -> CertificateRequest {
        CertificateRequest {
            github_login: "vasugarg".to_string(),
            hostname: "web-01".to_string(),
            public_key: user_public_key(),
            ttl_seconds: ttl,
        }
    }

    #[test]
    fn non_ed25519_key_is_rejected() {
        let ecdsa = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .expect("gen ecdsa");
        let err = CaKey::from_private_key(ecdsa, "ca-01").expect_err("not ed25519");
        assert!(matches!(err, CaError::NotEd25519 { .. }));
    }

    #[test]
    fn debug_never_prints_private_key() {
        let key = ed25519_signer("ca-01");
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("PRIVATE KEY"));
    }

    #[test]
    fn encrypt_roundtrips_and_stays_ed25519() {
        let key = ed25519_signer("ca-01");
        let encrypted = key.to_encrypted_openssh("p@ss", "ca-01").expect("encrypt");
        assert!(encrypted.contains("OPENSSH PRIVATE KEY"));
        let restored = CaKey::from_encrypted_openssh(&encrypted, "p@ss", "ca-01").expect("decrypt");
        assert_eq!(restored.public_openssh(), key.public_openssh());
        assert_eq!(restored.fingerprint(), key.fingerprint());
    }

    #[test]
    fn wrong_passphrase_fails_to_decrypt() {
        let key = ed25519_signer("ca-01");
        let encrypted = key.to_encrypted_openssh("right", "ca-01").expect("encrypt");
        let err = CaKey::from_encrypted_openssh(&encrypted, "wrong", "ca-01").expect_err("decrypt");
        assert!(matches!(err, CaError::Decrypt { .. }));
    }

    #[test]
    fn signs_with_expected_fields_and_ca_identity() {
        let key = ed25519_signer("ca-01");
        let response = key.sign_certificate(&request(300), now(), "ca-01").expect("sign");
        assert_eq!(response.principal, "vasugarg");
        assert_eq!(response.ttl_seconds, 300);
        assert_eq!(response.ca_key_id, "ca-01");
        assert_eq!(response.ca_fingerprint, key.fingerprint());
        assert!(response.fingerprint.starts_with("SHA256:"));

        let cert = Certificate::from_openssh(&response.certificate).expect("parse");
        assert_eq!(cert.key_id(), "ca-01");
        assert!(key.signed(&cert));
    }

    #[test]
    fn sign_uses_the_supplied_key_id_for_renames() {
        let key = ed25519_signer("ca-01");
        let response = key
            .sign_certificate(&request(300), now(), "ca-renamed")
            .expect("sign");
        assert_eq!(response.ca_key_id, "ca-renamed");
        let cert = Certificate::from_openssh(&response.certificate).expect("parse");
        assert_eq!(cert.key_id(), "ca-renamed");
    }

    #[test]
    fn ttl_bounds_are_enforced() {
        let key = ed25519_signer("ca-01");
        assert!(matches!(
            key.sign_certificate(&request(30), now(), "ca-01"),
            Err(CaError::InvalidRequest(_))
        ));
        assert!(matches!(
            key.sign_certificate(&request(7200), now(), "ca-01"),
            Err(CaError::InvalidRequest(_))
        ));
    }

    #[test]
    fn default_ttl_applied_for_zero() {
        let key = ed25519_signer("ca-01");
        let response = key.sign_certificate(&request(0), now(), "ca-01").expect("sign");
        assert_eq!(response.ttl_seconds, DEFAULT_TTL_SECONDS);
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        let key = ed25519_signer("ca-01");
        let mut req = request(300);
        req.public_key = "not a key".to_string();
        assert!(matches!(
            key.sign_certificate(&req, now(), "ca-01"),
            Err(CaError::InvalidRequest(_))
        ));
    }

    #[test]
    fn foreign_certificate_is_not_signed_by_this_key() {
        let key = ed25519_signer("ca-01");
        let other = ed25519_signer("ca-02");
        let response = other.sign_certificate(&request(300), now(), "ca-02").expect("sign");
        let cert = Certificate::from_openssh(&response.certificate).expect("parse");
        assert!(!key.signed(&cert));
        assert!(other.signed(&cert));
    }
}
