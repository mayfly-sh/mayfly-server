//! Certificate issuance and validation endpoints.
//!
//! - `POST /api/v1/certificates/issue`    — authenticate, authorize, sign.
//! - `GET  /api/v1/certificates/validate` — check a certificate against the CA.
//!
//! The issuance flow is provider-agnostic: Bearer token → provider identity
//! resolution (`?provider=`/body `provider`, default provider when absent) →
//! authorization → CA signing → audit → response. The principal is taken from
//! the authenticated identity's username, never from the request body, so a
//! caller cannot request a certificate for someone else, and no GitHub-specific
//! assumption remains.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use crate::audit::{NewAuditEntry, RequestAuditContext};
use crate::authz::{AuthzDecision, AuthzError};
use crate::ca::{CertificateRequest, CertificateResponse, CertificateValidation};
use crate::errors::ApiError;
use crate::request_id::RequestId;
use crate::routes::auth::{resolve_identity, BearerToken};
use crate::state::AppState;

/// Request body for `POST /api/v1/certificates/issue`.
///
/// The principal is intentionally absent — it is derived from the authenticated
/// identity. `provider` optionally selects the IdP that issued the bearer token
/// (default provider when absent), mirroring the device-flow endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct IssueCertificateRequest {
    /// The user's OpenSSH public key to be signed.
    pub public_key: String,
    /// Host the certificate is intended for (recorded in the audit log).
    pub hostname: String,
    /// Requested lifetime in seconds; `0`/absent selects the CA default.
    #[serde(default)]
    pub ttl_seconds: u32,
    /// Provider id the bearer token belongs to (defaults to the configured
    /// default provider).
    #[serde(default)]
    pub provider: Option<String>,
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
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    Json(request): Json<IssueCertificateRequest>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let ca = state.ca().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("certificate authority is not configured"))
    })?;

    // 1. Resolve identity through the selected provider (provider-agnostic).
    let identity = resolve_identity(&state, request.provider.as_deref(), &token).await?;

    // 2. Authorize (deny-by-default).
    if let AuthzDecision::Deny { reason } = state.authz().authorize(&identity) {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.username,
            provider = %identity.provider,
            reason = %reason,
            "certificate issuance denied",
        );
        // Audit the denial (fail-closed) before returning a generic 403.
        state
            .audit()
            .append_audit_event(
                NewAuditEntry::new("certificate.denied", identity.username.clone())
                    .with_subject(request.hostname.clone())
                    .with_metadata(json!({
                        "reason": reason,
                        "provider": identity.provider,
                        "subject": identity.subject,
                    })),
            )
            .await?;
        return Err(AuthzError::Denied { reason }.into());
    }

    // 3. Sign. Principal comes from the authenticated identity, not the body.
    let cert_request = CertificateRequest {
        principal: identity.username.clone(),
        hostname: request.hostname.clone(),
        public_key: request.public_key,
        ttl_seconds: request.ttl_seconds,
    };
    let response = ca.sign_certificate(&cert_request).await?;

    // 4. Audit the issuance (fail-closed). Records provider identity facts
    //    (provider/subject/realm/groups/roles) and the privacy-preserving client
    //    context, without ever logging the token.
    let client =
        RequestAuditContext::from_headers(&headers, Some(request_id.as_str()), state.clock().now())
            .with_provider(identity.provider.clone());
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new("certificate.issued", identity.username.clone())
                .with_subject(request.hostname.clone())
                .with_metadata(json!({
                    "serial": response.serial,
                    "fingerprint": response.fingerprint,
                    "principal": response.principal,
                    "ttl_seconds": response.ttl_seconds,
                    "valid_before": response.valid_before,
                    "ca_key_id": response.ca_key_id,
                    "ca_fingerprint": response.ca_fingerprint,
                    "provider": identity.provider,
                    "subject": identity.subject,
                    "realm": identity.realm,
                    "groups": identity.groups,
                    "roles": identity.roles,
                    "client": client.to_value(),
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
