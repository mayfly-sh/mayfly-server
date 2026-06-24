//! Certificate authority error type.

use thiserror::Error;

use crate::errors::ApiError;

/// Failures from loading the CA key or issuing certificates.
#[derive(Debug, Error)]
pub enum CaError {
    /// The CA private key file could not be read.
    #[error("ca key file '{path}' could not be read: {source}")]
    KeyFile {
        /// The configured key path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The configured passphrase environment variable was not set or empty.
    #[error("ca passphrase is not set (configure the passphrase env variable)")]
    PassphraseMissing,

    /// The key file could not be parsed as an OpenSSH private key.
    #[error("failed to parse ca private key: {0}")]
    Parse(String),

    /// The key could not be decrypted (typically a wrong passphrase).
    #[error("failed to decrypt ca private key (wrong passphrase?)")]
    Decrypt,

    /// The CA key is not an Ed25519 key.
    #[error("ca private key must be Ed25519, found {0}")]
    NotEd25519(String),

    /// A certificate request failed validation.
    #[error("invalid certificate request: {0}")]
    InvalidRequest(String),

    /// Certificate construction or signing failed.
    #[error("failed to sign certificate: {0}")]
    Sign(String),

    /// Encoding a key or certificate to OpenSSH format failed.
    #[error("failed to encode openssh data: {0}")]
    Encode(String),
}

impl From<CaError> for ApiError {
    fn from(err: CaError) -> Self {
        match err {
            // Client-correctable: a bad request (bad public key, TTL, etc.).
            CaError::InvalidRequest(msg) => ApiError::BadRequest(msg),
            // Everything else is a server/config failure; cause is logged only.
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}
