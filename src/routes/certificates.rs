//! Certificate issuance and validation endpoints.
//!
//! - `POST /api/v1/certificates/issue`    — authenticate, authorize, sign.
//! - `GET  /api/v1/certificates/validate` — check a certificate against the CA.
//!
//! The issuance flow is: Bearer GitHub token → GitHub identity lookup →
//! authorization → CA signing → audit → response. The principal is taken from
//! the authenticated GitHub identity, never from the request body, so a caller
//! cannot request a certificate for someone else.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::NewAuditEntry;
use crate::authz::{AuthzDecision, AuthzError};
use crate::ca::{CertificateRequest, CertificateResponse, CertificateValidation};
use crate::errors::ApiError;
use crate::routes::auth::{resolve_identity, BearerToken};
use crate::state::AppState;

/// Request body for `POST /api/v1/certificates/issue`.
///
/// The principal/`github_login` is intentionally absent — it is derived from
/// the authenticated identity.
#[derive(Debug, Clone, Deserialize)]
pub struct IssueCertificateRequest {
    /// The user's OpenSSH public key to be signed.
    pub public_key: String,
    /// Host the certificate is intended for (recorded in the audit log).
    pub hostname: String,
    /// Requested lifetime in seconds; `0`/absent selects the CA default.
    #[serde(default)]
    pub ttl_seconds: u32,
}

/// Request body for `GET /api/v1/certificates/validate`.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidateCertificateRequest {
    /// OpenSSH-formatted certificate to validate.
    pub certificate: String,
}

/// `POST /api/v1/certificates/issue` — issue a certificate for the bearer.
pub async fn issue(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Json(request): Json<IssueCertificateRequest>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let ca = state.ca().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("certificate authority is not configured"))
    })?;

    // 1. Resolve identity from the GitHub token.
    let identity = resolve_identity(&state, &token).await?;

    // 2. Authorize (deny-by-default).
    if let AuthzDecision::Deny { reason } = state.authz().authorize(&identity) {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.login,
            reason = %reason,
            "certificate issuance denied",
        );
        // Audit the denial (fail-closed) before returning a generic 403.
        state
            .audit()
            .append_audit_event(
                NewAuditEntry::new("certificate.denied", identity.login.clone())
                    .with_subject(request.hostname.clone())
                    .with_metadata(json!({ "reason": reason })),
            )
            .await?;
        return Err(AuthzError::Denied { reason }.into());
    }

    // 3. Sign. Principal comes from the authenticated identity, not the body.
    let cert_request = CertificateRequest {
        github_login: identity.login.clone(),
        hostname: request.hostname.clone(),
        public_key: request.public_key,
        ttl_seconds: request.ttl_seconds,
    };
    let response = ca.sign_certificate(&cert_request).await?;

    // 4. Audit the issuance (fail-closed).
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new("certificate.issued", identity.login.clone())
                .with_subject(request.hostname.clone())
                .with_metadata(json!({
                    "serial": response.serial,
                    "fingerprint": response.fingerprint,
                    "principal": response.principal,
                    "ttl_seconds": response.ttl_seconds,
                    "valid_before": response.valid_before,
                    "ca_key_id": response.ca_key_id,
                    "ca_fingerprint": response.ca_fingerprint,
                })),
        )
        .await?;

    Ok(Json(response))
}

/// `GET /api/v1/certificates/validate` — validate a certificate against the CA.
///
/// The certificate is supplied in the JSON body (kept out of the URL/query so
/// it never lands in access logs). No authentication is required.
pub async fn validate(
    State(state): State<AppState>,
    Json(request): Json<ValidateCertificateRequest>,
) -> Result<Json<CertificateValidation>, ApiError> {
    let ca = state.ca().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("certificate authority is not configured"))
    })?;
    let validation = ca.verify_certificate(&request.certificate, state.clock().now())?;
    Ok(Json(validation))
}
