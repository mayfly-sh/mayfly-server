//! Enrollment error type and its HTTP representation.
//!
//! [`EnrollmentError`] carries the stable, machine-readable error codes the API
//! contract promises (`TOKEN_INVALID`, `HOST_ALREADY_ENROLLED`, …) and maps
//! each to an HTTP status. It reuses the same `{ "error": { code, message } }`
//! envelope as [`crate::errors::ApiError`] so clients see one consistent shape.
//!
//! Security: client-visible messages are fixed, generic strings — they never
//! echo the enrollment token, the public key, or internal failure detail.
//! Operational failures collapse into [`EnrollmentError::Internal`], whose
//! cause is logged server-side and never returned.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Failures that can occur while enrolling a machine.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EnrollmentError {
    /// The token is malformed or does not exist.
    #[error("enrollment token is invalid")]
    TokenInvalid,

    /// The token exists but has passed its expiry.
    #[error("enrollment token has expired")]
    TokenExpired,

    /// The (single-use) token has already been consumed.
    #[error("enrollment token has already been used")]
    TokenAlreadyUsed,

    /// The request failed structural validation (e.g. an invalid hostname).
    #[error("{0}")]
    InvalidRequest(String),

    /// The supplied public key is not a valid Ed25519 OpenSSH key.
    #[error("public key is invalid")]
    PublicKeyInvalid,

    /// A machine with this hostname is already enrolled.
    #[error("a machine with this hostname is already enrolled")]
    HostAlreadyEnrolled,

    /// A machine with this public key is already enrolled.
    #[error("a machine with this public key is already enrolled")]
    PublicKeyAlreadyExists,

    /// An unexpected internal failure. The cause is logged, never returned.
    #[error("internal server error")]
    Internal(#[source] anyhow::Error),
}

impl EnrollmentError {
    /// Build an internal error from any error-like value.
    pub fn internal(err: impl Into<anyhow::Error>) -> Self {
        EnrollmentError::Internal(err.into())
    }

    /// HTTP status for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            // Authentication-style failures against the admission token.
            EnrollmentError::TokenInvalid | EnrollmentError::TokenExpired => {
                StatusCode::UNAUTHORIZED
            }
            // Malformed input.
            EnrollmentError::InvalidRequest(_) | EnrollmentError::PublicKeyInvalid => {
                StatusCode::BAD_REQUEST
            }
            // State conflicts: already-used token or already-enrolled identity.
            EnrollmentError::TokenAlreadyUsed
            | EnrollmentError::HostAlreadyEnrolled
            | EnrollmentError::PublicKeyAlreadyExists => StatusCode::CONFLICT,
            EnrollmentError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable, machine-readable error code returned in the response body.
    pub fn code(&self) -> &'static str {
        match self {
            EnrollmentError::TokenInvalid => "TOKEN_INVALID",
            EnrollmentError::TokenExpired => "TOKEN_EXPIRED",
            EnrollmentError::TokenAlreadyUsed => "TOKEN_ALREADY_USED",
            EnrollmentError::InvalidRequest(_) => "bad_request",
            EnrollmentError::PublicKeyInvalid => "PUBLIC_KEY_INVALID",
            EnrollmentError::HostAlreadyEnrolled => "HOST_ALREADY_ENROLLED",
            EnrollmentError::PublicKeyAlreadyExists => "PUBLIC_KEY_ALREADY_EXISTS",
            EnrollmentError::Internal(_) => "internal_error",
        }
    }

    /// Client-safe message. Internal errors are deliberately generic.
    pub fn client_message(&self) -> String {
        match self {
            EnrollmentError::Internal(_) => "internal server error".to_string(),
            other => other.to_string(),
        }
    }
}

/// Wire format mirrors [`crate::errors::ApiError`]: `{ "error": { code, message } }`.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for EnrollmentError {
    fn into_response(self) -> Response {
        if let EnrollmentError::Internal(cause) = &self {
            tracing::error!(error = ?cause, "internal error during machine enrollment");
        }

        let body = ErrorResponse {
            error: ErrorDetail {
                code: self.code(),
                message: self.client_message(),
            },
        };
        (self.status(), Json(body)).into_response()
    }
}

impl From<sqlx::Error> for EnrollmentError {
    fn from(err: sqlx::Error) -> Self {
        EnrollmentError::Internal(anyhow::Error::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_statuses_match_the_api_contract() {
        let cases = [
            (
                EnrollmentError::TokenInvalid,
                StatusCode::UNAUTHORIZED,
                "TOKEN_INVALID",
            ),
            (
                EnrollmentError::TokenExpired,
                StatusCode::UNAUTHORIZED,
                "TOKEN_EXPIRED",
            ),
            (
                EnrollmentError::TokenAlreadyUsed,
                StatusCode::CONFLICT,
                "TOKEN_ALREADY_USED",
            ),
            (
                EnrollmentError::PublicKeyInvalid,
                StatusCode::BAD_REQUEST,
                "PUBLIC_KEY_INVALID",
            ),
            (
                EnrollmentError::HostAlreadyEnrolled,
                StatusCode::CONFLICT,
                "HOST_ALREADY_ENROLLED",
            ),
            (
                EnrollmentError::PublicKeyAlreadyExists,
                StatusCode::CONFLICT,
                "PUBLIC_KEY_ALREADY_EXISTS",
            ),
        ];
        for (err, status, code) in cases {
            assert_eq!(err.status(), status);
            assert_eq!(err.code(), code);
        }
    }

    #[test]
    fn internal_error_hides_cause() {
        let err = EnrollmentError::internal(anyhow::anyhow!("token=mf_enroll_secret leaked"));
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code(), "internal_error");
        assert_eq!(err.client_message(), "internal server error");
        assert!(!err.client_message().contains("secret"));
    }

    #[tokio::test]
    async fn response_uses_standard_envelope() {
        let response = EnrollmentError::TokenExpired.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(value["error"]["code"], "TOKEN_EXPIRED");
        assert_eq!(value["error"]["message"], "enrollment token has expired");
    }
}
