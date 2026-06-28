//! Development self-signed certificate generation.
//!
//! In development, Mayfly generates a self-signed certificate for local use so
//! HTTPS works out of the box. The certificate covers `localhost`, `127.0.0.1`,
//! and `::1`, and is persisted under `.mayfly/dev-certs/` so it is reused across
//! restarts rather than regenerated each time.
//!
//! These certificates are for local development only. They are never generated
//! or used in production (see [`crate::environment::Environment`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, DnType, KeyPair, SanType};

use crate::tls::TlsError;

/// Default directory (relative to the working directory) for dev certificates.
pub const DEV_CERT_DIR: &str = ".mayfly/dev-certs";

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";

/// Filesystem locations of the development certificate and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevCertPaths {
    /// PEM certificate chain path.
    pub cert: PathBuf,
    /// PEM private key path.
    pub key: PathBuf,
}

/// Ensure a development certificate exists in `dir`, generating it only if
/// absent. Returns the paths to the certificate and key.
///
/// If exactly one of the two files exists, the pair is considered incomplete
/// and is regenerated; existing complete pairs are never overwritten.
pub fn ensure(dir: &Path) -> Result<DevCertPaths, TlsError> {
    let cert = dir.join(CERT_FILE);
    let key = dir.join(KEY_FILE);

    if cert.is_file() && key.is_file() {
        return Ok(DevCertPaths { cert, key });
    }

    generate(dir, &cert, &key)?;
    Ok(DevCertPaths { cert, key })
}

/// Generate and persist a fresh self-signed certificate.
fn generate(dir: &Path, cert_path: &Path, key_path: &Path) -> Result<(), TlsError> {
    std::fs::create_dir_all(dir)?;
    restrict_dir_permissions(dir)?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| TlsError::Generate(e.to_string()))?;
    let localhost = "localhost"
        .try_into()
        .map_err(|_| TlsError::Generate("invalid DNS SAN 'localhost'".to_string()))?;
    params.subject_alt_names = vec![
        SanType::DnsName(localhost),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "Mayfly Development");

    let key_pair = KeyPair::generate().map_err(|e| TlsError::Generate(e.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::Generate(e.to_string()))?;

    // Write the key first with restrictive permissions, then the certificate.
    write_private_key(key_path, &key_pair.serialize_pem())?;
    std::fs::write(cert_path, cert.pem())?;

    Ok(())
}

/// Write the private key with `0600` permissions on Unix.
fn write_private_key(path: &Path, pem: &str) -> Result<(), TlsError> {
    std::fs::write(path, pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Restrict the certificate directory to `0700` on Unix.
fn restrict_dir_permissions(dir: &Path) -> Result<(), TlsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("mayfly-devcerts-{}", uuid::Uuid::now_v7()))
    }

    #[test]
    fn generates_certificate_and_key() {
        let dir = temp_dir();
        let paths = ensure(&dir).expect("generate");
        assert!(paths.cert.is_file());
        assert!(paths.key.is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reuses_existing_certificate() {
        let dir = temp_dir();
        let first = ensure(&dir).expect("first");
        let original = std::fs::read(&first.cert).expect("read cert");

        let second = ensure(&dir).expect("second");
        let reused = std::fs::read(&second.cert).expect("read cert again");

        assert_eq!(first, second);
        assert_eq!(original, reused, "existing cert must not be regenerated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_file_is_a_certificate_block() {
        // Functional SAN coverage (the `localhost` name validating against the
        // chain) is asserted by the end-to-end TLS integration test, which
        // connects with ServerName("localhost").
        let dir = temp_dir();
        let paths = ensure(&dir).expect("generate");
        let pem = std::fs::read_to_string(&paths.cert).expect("read");
        assert!(pem.contains("BEGIN CERTIFICATE"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let paths = ensure(&dir).expect("generate");
        let mode = std::fs::metadata(&paths.key)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
