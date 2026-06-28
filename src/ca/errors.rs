//! Certificate authority error type.

use thiserror::Error;

use crate::errors::ApiError;

/// Failures from loading CA keys, validating the key set, managing CA
/// lifecycle, or issuing/verifying certificates.
///
/// Loading and validation variants carry the offending `key_id` so a failed
/// startup names exactly which CA is at fault. Key material and passphrases are
/// never included in any variant.
#[derive(Debug, Error)]
pub enum CaError {
    /// A CA private key file could not be read or written.
    #[error("ca key '{key_id}' file '{path}' could not be accessed: {source}")]
    KeyFile {
        /// The configured key id.
        key_id: String,
        /// The key path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The configured storage passphrase environment variable was unset/empty.
    #[error("ca storage passphrase environment variable '{env}' is not set or empty")]
    StoragePassphraseMissing {
        /// The environment variable that should have held the passphrase.
        env: String,
    },

    /// A CA private key could not be parsed as an OpenSSH private key.
    #[error("ca key '{key_id}' could not be parsed as an OpenSSH private key: {message}")]
    Parse {
        /// The configured key id.
        key_id: String,
        /// Parser error detail (never includes key material).
        message: String,
    },

    /// A CA key could not be decrypted (typically a wrong passphrase).
    #[error("ca key '{key_id}' could not be decrypted (wrong passphrase?)")]
    Decrypt {
        /// The configured key id.
        key_id: String,
    },

    /// A CA key is not an Ed25519 key.
    #[error("ca key '{key_id}' must be Ed25519, found {algorithm}")]
    NotEd25519 {
        /// The configured key id.
        key_id: String,
        /// The algorithm that was found instead.
        algorithm: String,
    },

    /// No CA keys exist at all where at least one is required.
    #[error("no ca keys are configured (at least one is required)")]
    NoKeysConfigured,

    /// More than [`crate::ca::MAX_CA_KEYS`] keys exist.
    #[error("too many ca keys: {count} (maximum is {max})")]
    TooManyKeys {
        /// The current key count.
        count: usize,
        /// The maximum supported count.
        max: usize,
    },

    /// Every CA key is disabled.
    #[error("no enabled ca keys (at least one key must be enabled)")]
    NoEnabledKeys,

    /// Disabling the requested CA would leave zero enabled keys.
    #[error("cannot disable ca '{key_id}': it is the last enabled CA")]
    CannotDisableLast {
        /// The key id that was asked to be disabled.
        key_id: String,
    },

    /// Retiring an enabled CA is refused: it must be disabled first so the
    /// bundle stops advertising the key before its material is destroyed.
    #[error("cannot retire ca '{key_id}': it is still enabled (disable it first)")]
    CannotRetireEnabled {
        /// The key id that was asked to be retired.
        key_id: String,
    },

    /// Two keys share the same `key_id`.
    #[error("duplicate ca key id '{0}'")]
    DuplicateKeyId(String),

    /// Two distinct key ids resolve to the same public key.
    #[error("duplicate ca public key shared by key ids '{first}' and '{second}'")]
    DuplicatePublicKey {
        /// The first key id that presented this public key.
        first: String,
        /// The second key id that presented the same public key.
        second: String,
    },

    /// Two distinct key ids resolve to the same SHA-256 fingerprint.
    #[error("duplicate ca key fingerprint shared by key ids '{first}' and '{second}'")]
    DuplicateFingerprint {
        /// The first key id with this fingerprint.
        first: String,
        /// The second key id with the same fingerprint.
        second: String,
    },

    /// A requested CA id does not exist.
    #[error("ca '{0}' was not found")]
    NotFound(String),

    /// A `key_id` is already in use by another CA.
    #[error("ca key id '{0}' is already in use")]
    KeyIdInUse(String),

    /// A public key is already managed by another CA.
    #[error("ca public key is already managed (matches key id '{0}')")]
    PublicKeyInUse(String),

    /// A fingerprint is already managed by another CA.
    #[error("ca fingerprint is already managed (matches key id '{0}')")]
    FingerprintInUse(String),

    /// The supplied passphrase does not match the configured storage passphrase.
    #[error("passphrase does not match the configured CA storage passphrase")]
    PassphraseMismatch,

    /// A certificate request failed validation.
    #[error("invalid certificate request: {0}")]
    InvalidRequest(String),

    /// An admin request body failed validation.
    #[error("{0}")]
    InvalidInput(String),

    /// Certificate construction or signing failed.
    #[error("failed to sign certificate: {0}")]
    Sign(String),

    /// Encoding a key or certificate to OpenSSH format failed.
    #[error("failed to encode openssh data: {0}")]
    Encode(String),

    /// A storage (database) operation failed.
    #[error("ca storage error: {0}")]
    Storage(String),
}

impl From<sqlx::Error> for CaError {
    fn from(err: sqlx::Error) -> Self {
        CaError::Storage(err.to_string())
    }
}

impl From<CaError> for ApiError {
    fn from(err: CaError) -> Self {
        match err {
            // Client-correctable bad input.
            CaError::InvalidRequest(msg) | CaError::InvalidInput(msg) => ApiError::BadRequest(msg),
            CaError::PassphraseMismatch => {
                ApiError::BadRequest("passphrase does not match the CA storage passphrase".into())
            }
            // Resource lookups.
            CaError::NotFound(id) => ApiError::NotFound(format!("ca '{id}' was not found")),
            // Uniqueness / state conflicts.
            CaError::KeyIdInUse(_)
            | CaError::PublicKeyInUse(_)
            | CaError::FingerprintInUse(_)
            | CaError::DuplicateKeyId(_)
            | CaError::DuplicatePublicKey { .. }
            | CaError::DuplicateFingerprint { .. }
            | CaError::CannotDisableLast { .. }
            | CaError::CannotRetireEnabled { .. } => ApiError::Conflict(err.to_string()),
            // Everything else is a server/config failure; cause is logged only.
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}
