//! GitHub client errors and their mapping to [`ApiError`].
//!
//! Errors never carry tokens, secrets, or device codes — only coarse,
//! non-sensitive context safe to log server-side.

use crate::errors::ApiError;
use thiserror::Error;

/// Failures from talking to GitHub.
#[derive(Debug, Error)]
pub enum GitHubError {
    /// Network/transport failure (DNS, TLS, timeout, connection reset).
    #[error("github transport error: {0}")]
    Transport(String),

    /// GitHub returned a status we do not handle for this call.
    #[error("github returned unexpected status {status}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: u16,
    },

    /// GitHub's response body could not be parsed into the expected shape.
    #[error("failed to decode github response: {0}")]
    Decode(String),

    /// The supplied access token was rejected by GitHub (401).
    #[error("github rejected the access token")]
    Unauthorized,

    /// GitHub rate-limited the request (403/429 with rate-limit headers).
    #[error("github rate limit exceeded")]
    RateLimited,

    /// The device code was rejected by GitHub (e.g. `incorrect_device_code`).
    #[error("github rejected the device code")]
    InvalidDeviceCode,
}

impl From<GitHubError> for ApiError {
    fn from(err: GitHubError) -> Self {
        match err {
            GitHubError::Unauthorized => {
                ApiError::Unauthorized("the access token is invalid or expired".to_string())
            }
            GitHubError::RateLimited => {
                ApiError::TooManyRequests("upstream rate limit exceeded; retry later".to_string())
            }
            GitHubError::InvalidDeviceCode => {
                ApiError::BadRequest("the device_code is invalid".to_string())
            }
            // Transport, unexpected status, and decode failures are upstream
            // problems the client cannot fix; surface a generic 500 and log the
            // detail server-side (handled by ApiError::Internal).
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}
