//! Authorization error type and its mapping to [`ApiError`].

use thiserror::Error;

use crate::errors::ApiError;

/// An authorization failure.
#[derive(Debug, Error)]
pub enum AuthzError {
    /// The identity is not permitted by the configured allowlists.
    #[error("access denied: {reason}")]
    Denied {
        /// Server-side explanation (never returned verbatim to the client).
        reason: String,
    },
}

impl From<AuthzError> for ApiError {
    fn from(err: AuthzError) -> Self {
        // The detailed reason is logged/audited by the caller. We return a
        // generic 403 so allowlist contents are not disclosed to probers.
        match err {
            AuthzError::Denied { .. } => ApiError::Forbidden("access denied".to_string()),
        }
    }
}
