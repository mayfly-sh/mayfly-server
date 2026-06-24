//! In-memory SSH certificate authority.
//!
//! The CA private key is loaded and decrypted exactly once at startup and held
//! only in memory (the `ssh-key` `PrivateKey` zeroizes its secret material on
//! drop). All signing is performed in-process with the `ssh-key` crate — no
//! `ssh-keygen`, no shell execution, ever.

use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use ssh_key::certificate::{Builder, CertType, Certificate};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};

use crate::ca::errors::CaError;
use crate::ca::models::{
    CertificateRequest, CertificateResponse, CertificateValidation, DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS, MIN_TTL_SECONDS,
};
use crate::clock::Clock;
use crate::config::CaConfig;

/// Non-critical extensions granted on every issued user certificate.
const STANDARD_EXTENSIONS: [&str; 3] = [
    "permit-pty",
    "permit-port-forwarding",
    "permit-agent-forwarding",
];

/// An in-memory SSH certificate authority.
///
/// Deliberately does not implement `Debug`: it owns decrypted key material.
pub struct CaService {
    private_key: PrivateKey,
    key_id: String,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for CaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("CaService")
            .field("key_id", &self.key_id)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl CaService {
    /// Load and decrypt the CA key from configuration, reading the passphrase
    /// from the configured environment variable.
    ///
    /// Fails fast if the passphrase env var is unset/empty, the file is
    /// missing/unparseable, decryption fails, or the key is not Ed25519.
    pub fn from_config(config: &CaConfig, clock: Arc<dyn Clock>) -> Result<Self, CaError> {
        let passphrase = std::env::var(&config.passphrase_env).unwrap_or_default();
        if passphrase.trim().is_empty() {
            return Err(CaError::PassphraseMissing);
        }
        Self::load(&config.private_key_path, &passphrase, &config.key_id, clock)
    }

    /// Load and decrypt the CA key from an explicit path and passphrase.
    pub fn load(
        key_path: &Path,
        passphrase: &str,
        key_id: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, CaError> {
        let bytes = std::fs::read(key_path).map_err(|source| CaError::KeyFile {
            path: key_path.display().to_string(),
            source,
        })?;

        let key = PrivateKey::from_openssh(&bytes).map_err(|err| CaError::Parse(err.to_string()))?;

        let decrypted = if key.is_encrypted() {
            if passphrase.is_empty() {
                return Err(CaError::PassphraseMissing);
            }
            key.decrypt(passphrase).map_err(|_| CaError::Decrypt)?
        } else {
            key
        };

        if !matches!(decrypted.algorithm(), Algorithm::Ed25519) {
            return Err(CaError::NotEd25519(decrypted.algorithm().as_str().to_string()));
        }

        Ok(Self {
            private_key: decrypted,
            key_id: key_id.into(),
            clock,
        })
    }

    /// The CA's public key in OpenSSH format (for distribution to hosts).
    pub fn get_ca_public_key(&self) -> Result<String, CaError> {
        self.private_key
            .public_key()
            .to_openssh()
            .map_err(|err| CaError::Encode(err.to_string()))
    }

    /// Validate an OpenSSH certificate against this CA at the given time.
    ///
    /// Reports whether the signature chains to this CA (cryptographically
    /// verified, not merely a fingerprint match) and whether `at` falls within
    /// the certificate's validity window.
    pub fn verify_certificate(
        &self,
        certificate: &str,
        at: DateTime<Utc>,
    ) -> Result<CertificateValidation, CaError> {
        let cert = Certificate::from_openssh(certificate)
            .map_err(|err| CaError::InvalidRequest(format!("invalid certificate: {err}")))?;

        let ca_fingerprint = self.private_key.public_key().fingerprint(HashAlg::Sha256);

        // Verify the signature and issuer at a time guaranteed to be inside the
        // certificate's own window (valid_after), so issuer verification is
        // independent of the current-time expiry check below. This actually
        // checks the cryptographic signature — a forger cannot pass by merely
        // claiming our (public) CA key as the signing key.
        let issued_by_this_ca = cert
            .validate_at(cert.valid_after(), [&ca_fingerprint])
            .is_ok();

        let now = u64::try_from(at.timestamp()).unwrap_or(0);
        let time_reason = if now < cert.valid_after() {
            Some("certificate is not yet valid".to_string())
        } else if now > cert.valid_before() {
            Some("certificate has expired".to_string())
        } else {
            None
        };

        let reason = if !issued_by_this_ca {
            Some("certificate was not issued by this CA or its signature is invalid".to_string())
        } else {
            time_reason.clone()
        };

        Ok(CertificateValidation {
            valid: issued_by_this_ca && time_reason.is_none(),
            reason,
            issued_by_this_ca,
            principals: cert.valid_principals().to_vec(),
            serial: cert.serial(),
            valid_after: format_timestamp(cert.valid_after()),
            valid_before: format_timestamp(cert.valid_before()),
        })
    }

    /// Issue and sign an SSH user certificate for the request.
    pub fn sign_certificate(
        &self,
        request: &CertificateRequest,
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

        // Serial and validity are anchored to the injected clock.
        let now = self.clock.now().timestamp();
        let valid_after = u64::try_from(now)
            .map_err(|_| CaError::Sign("clock is before the unix epoch".to_string()))?;
        let serial = valid_after;
        let valid_before = valid_after + u64::from(ttl);

        let mut builder = Builder::new_with_random_nonce(&mut OsRng, subject, valid_after, valid_before)
            .map_err(sign_err)?;
        builder.serial(serial).map_err(sign_err)?;
        builder.key_id(&self.key_id).map_err(sign_err)?;
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

fn format_timestamp(seconds: u64) -> String {
    DateTime::<Utc>::from_timestamp(seconds as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use ssh_key::{EcdsaCurve, LineEnding};
    use std::path::PathBuf;

    const TEST_PASSPHRASE: &str = "mayfly-test-passphrase";

    fn test_key_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ca_test")
    }

    fn fixed_clock() -> Arc<dyn Clock> {
        Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap())
    }

    fn load_test_ca() -> CaService {
        CaService::load(&test_key_path(), TEST_PASSPHRASE, "mayfly-ca", fixed_clock())
            .expect("load test ca")
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mayfly_{}_{}", std::process::id(), name))
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
    fn loads_valid_encrypted_key_and_exposes_public_key() {
        let ca = load_test_ca();
        let public_key = ca.get_ca_public_key().expect("public key");
        let parsed = PublicKey::from_openssh(&public_key).expect("parse");
        assert!(matches!(parsed.algorithm(), Algorithm::Ed25519));
    }

    #[test]
    fn missing_passphrase_fails() {
        let err = CaService::load(&test_key_path(), "", "mayfly-ca", fixed_clock())
            .expect_err("missing passphrase");
        assert!(matches!(err, CaError::PassphraseMissing));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let err = CaService::load(&test_key_path(), "not-the-passphrase", "mayfly-ca", fixed_clock())
            .expect_err("wrong passphrase");
        assert!(matches!(err, CaError::Decrypt));
    }

    #[test]
    fn missing_key_file_fails() {
        let err = CaService::load(
            &temp_path("does_not_exist_key"),
            TEST_PASSPHRASE,
            "mayfly-ca",
            fixed_clock(),
        )
        .expect_err("missing file");
        assert!(matches!(err, CaError::KeyFile { .. }));
    }

    #[test]
    fn invalid_key_fails_to_parse() {
        let path = temp_path("garbage_key");
        std::fs::write(&path, b"this is not an openssh private key").expect("write");
        let err = CaService::load(&path, TEST_PASSPHRASE, "mayfly-ca", fixed_clock())
            .expect_err("invalid key");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, CaError::Parse(_)));
    }

    #[test]
    fn non_ed25519_key_is_rejected() {
        // Generate an (unencrypted) ECDSA key and confirm it is rejected.
        let ecdsa = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .expect("gen ecdsa");
        let path = temp_path("ecdsa_key");
        std::fs::write(&path, ecdsa.to_openssh(LineEnding::LF).expect("encode").as_bytes())
            .expect("write");
        let err = CaService::load(&path, "", "mayfly-ca", fixed_clock()).expect_err("not ed25519");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, CaError::NotEd25519(_)));
    }

    #[test]
    fn signs_certificate_with_expected_fields() {
        let ca = load_test_ca();
        let response = ca.sign_certificate(&request(300)).expect("sign");

        assert_eq!(response.principal, "vasugarg");
        assert_eq!(response.ttl_seconds, 300);
        // Clock fixed at 2026-06-24T12:00:00Z.
        let expected_serial = chrono::DateTime::parse_from_rfc3339("2026-06-24T12:00:00Z")
            .unwrap()
            .timestamp() as u64;
        assert_eq!(response.serial, expected_serial);
        assert!(response.fingerprint.starts_with("SHA256:"));
        assert!(response.certificate.contains("ssh-ed25519-cert-v01@openssh.com"));
    }

    #[test]
    fn default_ttl_is_applied_for_zero() {
        let ca = load_test_ca();
        let response = ca.sign_certificate(&request(0)).expect("sign");
        assert_eq!(response.ttl_seconds, DEFAULT_TTL_SECONDS);
    }

    #[test]
    fn ttl_below_minimum_is_rejected() {
        let ca = load_test_ca();
        let err = ca.sign_certificate(&request(30)).expect_err("too short");
        assert!(matches!(err, CaError::InvalidRequest(_)));
    }

    #[test]
    fn ttl_above_maximum_is_rejected() {
        let ca = load_test_ca();
        let err = ca.sign_certificate(&request(7200)).expect_err("too long");
        assert!(matches!(err, CaError::InvalidRequest(_)));
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        let ca = load_test_ca();
        let mut req = request(300);
        req.public_key = "not a public key".to_string();
        let err = ca.sign_certificate(&req).expect_err("bad key");
        assert!(matches!(err, CaError::InvalidRequest(_)));
    }

    #[test]
    fn produced_certificate_parses_and_verifies() {
        let ca = load_test_ca();
        let response = ca.sign_certificate(&request(600)).expect("sign");

        let cert = Certificate::from_openssh(&response.certificate).expect("parse cert");

        // Principal embedded.
        assert_eq!(cert.valid_principals(), &["vasugarg".to_string()]);
        // Serial matches.
        assert_eq!(cert.serial(), response.serial);
        // Validity matches the response and the requested TTL.
        assert_eq!(cert.valid_before() - cert.valid_after(), 600);
        assert_eq!(cert.valid_after(), response.serial);
        // Certificate type is user.
        assert_eq!(cert.cert_type(), CertType::User);
        // Standard extensions present.
        for extension in STANDARD_EXTENSIONS {
            assert!(
                cert.extensions().contains_key(extension),
                "missing extension {extension}"
            );
        }
        // Key id is the configured CA key id.
        assert_eq!(cert.key_id(), "mayfly-ca");
    }

    #[test]
    fn verify_certificate_accepts_a_fresh_certificate() {
        let ca = load_test_ca();
        let response = ca.sign_certificate(&request(300)).expect("sign");

        // Same clock time as issuance: within the window.
        let validation = ca
            .verify_certificate(&response.certificate, fixed_clock().now())
            .expect("verify");
        assert!(validation.valid);
        assert!(validation.issued_by_this_ca);
        assert_eq!(validation.reason, None);
        assert_eq!(validation.principals, vec!["vasugarg".to_string()]);
        assert_eq!(validation.serial, response.serial);
    }

    #[test]
    fn verify_certificate_reports_expiry() {
        let ca = load_test_ca();
        let response = ca.sign_certificate(&request(300)).expect("sign");

        // Evaluate well after valid_before.
        let later = fixed_clock().now() + chrono::TimeDelta::seconds(10_000);
        let validation = ca.verify_certificate(&response.certificate, later).expect("verify");
        assert!(!validation.valid);
        assert!(validation.issued_by_this_ca);
        assert_eq!(validation.reason.as_deref(), Some("certificate has expired"));
    }

    #[test]
    fn verify_certificate_rejects_foreign_ca() {
        // A certificate signed by a different CA must not validate against us.
        let other = CaService::load(&test_key_path(), TEST_PASSPHRASE, "mayfly-ca", fixed_clock())
            .expect("load");
        // Build a second, unrelated CA in memory.
        let foreign_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("gen");
        let foreign = CaService {
            private_key: foreign_key,
            key_id: "foreign".to_string(),
            clock: fixed_clock(),
        };
        let response = foreign.sign_certificate(&request(300)).expect("sign");

        let validation = other
            .verify_certificate(&response.certificate, fixed_clock().now())
            .expect("verify");
        assert!(!validation.valid);
        assert!(!validation.issued_by_this_ca);
    }

    #[test]
    fn certificate_is_signed_by_this_ca() {
        let ca = load_test_ca();
        let response = ca.sign_certificate(&request(300)).expect("sign");
        let cert = Certificate::from_openssh(&response.certificate).expect("parse");

        let ca_key = PublicKey::from_openssh(&ca.get_ca_public_key().unwrap()).unwrap();
        // validate_at with the CA fingerprint confirms the signature chains to us.
        let ca_fingerprint = ca_key.fingerprint(HashAlg::Sha256);
        let result = cert.validate_at(cert.valid_after(), [&ca_fingerprint]);
        assert!(result.is_ok(), "certificate must validate against the CA");
    }
}
