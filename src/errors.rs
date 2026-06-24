//! Application error types.
//!
//! [`AuditError`] is the audit subsystem's domain error. [`ApiError`] is the
//! single error type returned from HTTP handlers; it owns the mapping from
//! internal failures to HTTP status codes and to a stable JSON error body.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Errors surfaced by the audit subsystem.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Hash computation or validation failed.
    #[error("audit hash error: {0}")]
    Hash(String),

    /// Chain verification detected a broken link.
    #[error("audit chain broken at position {position}: {reason}")]
    ChainBroken {
        /// `chain_position` of the first invalid entry.
        position: i64,
        /// Human-readable explanation.
        reason: String,
    },

    /// Database persistence error.
    #[error("audit repository error: {0}")]
    Repository(#[from] sqlx::Error),

    /// Entry not found.
    #[error("audit entry not found at chain position {0}")]
    NotFound(i64),
}

/// The unified error type returned by HTTP handlers.
///
/// Each variant maps to a specific HTTP status and a stable machine-readable
/// `code`. The [`ApiError::Internal`] variant intentionally hides its cause
/// from clients (logged server-side only) to avoid leaking internals.
///
/// ## Client-message contract
///
/// The `String` carried by the client-visible variants (`BadRequest`,
/// `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`) is returned verbatim in
/// the response body. It **must not** contain secrets, raw internal errors, or
/// unsanitized attacker-controlled input. Put diagnostic detail in
/// [`ApiError::Internal`] (logged, never returned) instead.
///
/// Marked `#[non_exhaustive]` so new variants (e.g. rate limiting) can be added
/// without breaking external `match`es.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApiError {
    /// 400 — the request was malformed or failed validation.
    #[error("{0}")]
    BadRequest(String),

    /// 401 — authentication is required or failed.
    #[error("{0}")]
    Unauthorized(String),

    /// 403 — the caller is authenticated but not permitted.
    #[error("{0}")]
    Forbidden(String),

    /// 404 — the requested resource does not exist.
    #[error("{0}")]
    NotFound(String),

    /// 409 — the request conflicts with current state.
    #[error("{0}")]
    Conflict(String),

    /// 500 — an unexpected internal failure. Cause is logged, not returned.
    #[error("internal server error")]
    Internal(#[source] anyhow::Error),
}

impl ApiError {
    /// HTTP status code for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable, machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::Internal(_) => "internal_error",
        }
    }

    /// Client-safe message. Internal errors are deliberately generic.
    pub fn client_message(&self) -> String {
        match self {
            ApiError::Internal(_) => "internal server error".to_string(),
            other => other.to_string(),
        }
    }

    /// Construct an internal error from any error-like value.
    pub fn internal(err: impl Into<anyhow::Error>) -> Self {
        ApiError::Internal(err.into())
    }
}

/// Wire format for error responses: `{ "error": { "code", "message" } }`.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log the full cause of internal errors server-side; clients never see it.
        if let ApiError::Internal(cause) = &self {
            tracing::error!(error = ?cause, "internal error serving request");
        }

        let status = self.status();
        let needs_auth_challenge = matches!(self, ApiError::Unauthorized(_));
        let body = ErrorResponse {
            error: ErrorDetail {
                code: self.code(),
                message: self.client_message(),
            },
        };

        let mut response = (status, Json(body)).into_response();

        // RFC 7235: a 401 response must advertise the authentication scheme.
        if needs_auth_challenge {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }

        response
    }
}

impl From<AuditError> for ApiError {
    fn from(err: AuditError) -> Self {
        match err {
            AuditError::NotFound(position) => {
                ApiError::NotFound(format!("audit entry not found at chain position {position}"))
            }
            // Tamper detection is a security event: emit a distinct, high-severity
            // signal before collapsing into a generic internal error for the client.
            AuditError::ChainBroken { position, reason } => {
                tracing::error!(
                    target: "mayfly::security",
                    position,
                    reason = %reason,
                    "audit chain integrity violation detected"
                );
                ApiError::Internal(anyhow::anyhow!(
                    "audit chain integrity violation at position {position}: {reason}"
                ))
            }
            // Other integrity and persistence failures are internal concerns.
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn maps_variants_to_expected_status_and_code() {
        let cases = [
            (ApiError::BadRequest("x".into()), StatusCode::BAD_REQUEST, "bad_request"),
            (ApiError::Unauthorized("x".into()), StatusCode::UNAUTHORIZED, "unauthorized"),
            (ApiError::Forbidden("x".into()), StatusCode::FORBIDDEN, "forbidden"),
            (ApiError::NotFound("x".into()), StatusCode::NOT_FOUND, "not_found"),
            (ApiError::Conflict("x".into()), StatusCode::CONFLICT, "conflict"),
        ];

        for (err, status, code) in cases {
            assert_eq!(err.status(), status);
            assert_eq!(err.code(), code);
        }
    }

    #[test]
    fn internal_error_hides_cause_from_client() {
        let err = ApiError::internal(anyhow::anyhow!("secret db connection string leaked"));
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code(), "internal_error");
        assert_eq!(err.client_message(), "internal server error");
        assert!(!err.client_message().contains("secret"));
    }

    #[tokio::test]
    async fn response_body_uses_standard_envelope() {
        let response = ApiError::NotFound("user 7".into()).into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(value["error"]["code"], "not_found");
        assert_eq!(value["error"]["message"], "user 7");
    }

    #[tokio::test]
    async fn unauthorized_sets_www_authenticate_header() {
        let response = ApiError::Unauthorized("token required".into()).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("challenge header");
        assert_eq!(challenge, "Bearer");
    }

    #[test]
    fn audit_not_found_maps_to_api_not_found() {
        let api: ApiError = AuditError::NotFound(3).into();
        assert_eq!(api.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn audit_integrity_failure_maps_to_internal() {
        let api: ApiError = AuditError::ChainBroken {
            position: 2,
            reason: "tamper".into(),
        }
        .into();
        assert_eq!(api.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(api.client_message(), "internal server error");
    }
}
