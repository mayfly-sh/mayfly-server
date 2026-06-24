//! Rustls server configuration.
//!
//! Builds a TLS 1.3-only [`rustls::ServerConfig`] that advertises ALPN for
//! HTTP/2 and HTTP/1.1. The crypto backend is `ring`; there is no OpenSSL,
//! aws-lc, or native-tls anywhere in the path.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// ALPN protocol identifiers, in server-preference order: HTTP/2 then HTTP/1.1.
pub const ALPN_H2: &[u8] = b"h2";
/// HTTP/1.1 ALPN identifier.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Errors building or loading TLS material.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Filesystem error reading certificate or key material.
    #[error("tls io error: {0}")]
    Io(#[from] std::io::Error),

    /// PEM parsing failed.
    #[error("failed to parse PEM data: {0}")]
    Pem(String),

    /// No private key was present in the key file.
    #[error("no private key found in '{0}'")]
    NoPrivateKey(String),

    /// Rustls rejected the certificate/key pair.
    #[error("invalid certificate material: {0}")]
    Rustls(String),

    /// Development certificate generation failed.
    #[error("failed to generate development certificate: {0}")]
    Generate(String),
}

/// Load a PEM certificate chain and private key from disk.
pub fn load_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let cert_bytes = std::fs::read(cert_path)?;
    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| TlsError::Pem(err.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::Pem(format!(
            "no certificates found in '{}'",
            cert_path.display()
        )));
    }

    let key_bytes = std::fs::read(key_path)?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .map_err(|err| TlsError::Pem(err.to_string()))?
        .ok_or_else(|| TlsError::NoPrivateKey(key_path.display().to_string()))?;

    Ok((certs, key))
}

/// Build a TLS 1.3-only server configuration with ALPN h2 + http/1.1.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    // Use the ring provider explicitly so we never depend on a process-global
    // default provider being installed. Only TLS 1.3 is permitted.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TlsError::Rustls(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| TlsError::Rustls(err.to_string()))?;

    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_certs;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("mayfly-tls-{}", uuid::Uuid::now_v7()))
    }

    #[test]
    fn server_config_advertises_h2_and_http11() {
        let dir = temp_dir();
        let paths = dev_certs::ensure(&dir).expect("dev certs");
        let (certs, key) = load_pem(&paths.cert, &paths.key).expect("load pem");
        let config = server_config(certs, key).expect("server config");

        assert_eq!(
            config.alpn_protocols,
            vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_pem_errors_on_missing_files() {
        let err = load_pem(Path::new("/nonexistent/cert.pem"), Path::new("/nonexistent/key.pem"))
            .expect_err("missing files");
        assert!(matches!(err, TlsError::Io(_)));
    }
}
