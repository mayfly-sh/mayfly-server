//! CA management admin API.
//!
//! - `POST   /api/v1/admin/ca/generate` — generate a new encrypted Ed25519 CA.
//! - `POST   /api/v1/admin/ca/import`   — import an existing encrypted CA key.
//! - `GET    /api/v1/admin/ca`          — list all CA metadata.
//! - `GET    /api/v1/admin/ca/{id}`     — detailed metadata for one CA.
//! - `PATCH  /api/v1/admin/ca/{id}`     — enable / disable / rename a CA.
//!
//! Every endpoint authenticates a GitHub Bearer token and authorizes it with
//! the same deny-by-default policy as certificate issuance. There is
//! intentionally no delete: disabled CAs are retained for certificate
//! validation and audit history. Private key material is never returned, and
//! passphrases are never logged or audited.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::NewAuditEntry;
use crate::authz::{AuthzDecision, AuthzError, Identity};
use crate::bundle::{BundleService, FleetStatus, RetirementAssessment};
use crate::ca::{CaManager, CaRecord};
use crate::errors::ApiError;
use crate::routes::auth::{resolve_identity, BearerToken};
use crate::state::AppState;

/// Request body for `POST /api/v1/admin/ca/generate`.
#[derive(Debug, Clone, Deserialize)]
pub struct GenerateCaRequest {
    /// Operator-assigned identifier for the new CA.
    pub key_id: String,
    /// Passphrase to protect the key at rest. Must match the server's storage
    /// passphrase. Never logged.
    pub passphrase: String,
}

/// Request body for `POST /api/v1/admin/ca/import`.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportCaRequest {
    /// Operator-assigned identifier for the imported CA.
    pub key_id: String,
    /// The OpenSSH-armored private key to import (may be encrypted).
    pub private_key: String,
    /// Passphrase that decrypts `private_key`. Never logged.
    #[serde(default)]
    pub passphrase: String,
}

/// Request body for `PATCH /api/v1/admin/ca/{id}`.
///
/// All fields are optional; at least one must be present. Key material is never
/// modified.
#[derive(Debug, Clone, Deserialize)]
pub struct PatchCaRequest {
    /// `true` to enable, `false` to disable.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// New `key_id` to rename the CA to.
    #[serde(default)]
    pub key_id: Option<String>,
}

/// `POST /api/v1/admin/ca/generate`
pub async fn generate(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Json(request): Json<GenerateCaRequest>,
) -> Result<(StatusCode, Json<CaRecord>), ApiError> {
    let identity = authorize_admin(&state, &token, "ca.generate").await?;
    let ca = require_ca(&state)?;

    let record = ca
        .generate(request.key_id.trim(), &request.passphrase)
        .await?;
    audit_lifecycle(&state, &identity, "ca.generated", &record).await?;
    Ok((StatusCode::CREATED, Json(record)))
}

/// `POST /api/v1/admin/ca/import`
pub async fn import(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Json(request): Json<ImportCaRequest>,
) -> Result<(StatusCode, Json<CaRecord>), ApiError> {
    let identity = authorize_admin(&state, &token, "ca.import").await?;
    let ca = require_ca(&state)?;

    let record = ca
        .import(
            request.key_id.trim(),
            &request.private_key,
            &request.passphrase,
        )
        .await?;
    audit_lifecycle(&state, &identity, "ca.imported", &record).await?;
    Ok((StatusCode::CREATED, Json(record)))
}

/// `GET /api/v1/admin/ca`
pub async fn list(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> Result<Json<Vec<CaRecord>>, ApiError> {
    authorize_admin(&state, &token, "ca.list").await?;
    let ca = require_ca(&state)?;
    Ok(Json(ca.list()))
}

/// `GET /api/v1/admin/ca/{id}`
pub async fn get_one(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(id): Path<String>,
) -> Result<Json<CaRecord>, ApiError> {
    authorize_admin(&state, &token, "ca.get").await?;
    let ca = require_ca(&state)?;
    ca.get(&id)
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("ca '{id}' was not found")))
}

/// `PATCH /api/v1/admin/ca/{id}`
pub async fn patch(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(id): Path<String>,
    Json(request): Json<PatchCaRequest>,
) -> Result<Json<CaRecord>, ApiError> {
    let identity = authorize_admin(&state, &token, "ca.patch").await?;
    let ca = require_ca(&state)?;

    if request.enabled.is_none() && request.key_id.is_none() {
        return Err(ApiError::BadRequest(
            "patch must set at least one of 'enabled' or 'key_id'".to_string(),
        ));
    }

    // Apply rename first so a subsequent enable/disable audit reflects the new
    // id. Each mutation goes through the manager, which persists and (for
    // enable/disable) bumps the bundle generation.
    let mut record = ca
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("ca '{id}' was not found")))?;

    if let Some(new_key_id) = request.key_id.as_deref() {
        let new_key_id = new_key_id.trim();
        if new_key_id != record.key_id {
            record = ca.rename(&id, new_key_id).await?;
            audit_lifecycle(&state, &identity, "ca.renamed", &record).await?;
        }
    }

    if let Some(enabled) = request.enabled {
        let changed = enabled != record.enabled;
        record = if enabled {
            ca.enable(&id).await?
        } else {
            ca.disable(&id).await?
        };
        if changed {
            let action = if enabled { "ca.enabled" } else { "ca.disabled" };
            audit_lifecycle(&state, &identity, action, &record).await?;
        }
    }

    Ok(Json(record))
}

/// Request body for `POST /api/v1/admin/ca/{id}/retire`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RetireCaRequest {
    /// When `true`, retire even if the safety assessment says it is unsafe.
    /// Forced retirement emits a security warning and a dedicated audit event.
    #[serde(default)]
    pub force: bool,
}

/// `GET /api/v1/admin/bundle/status` — fleet rollout visibility.
pub async fn bundle_status(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> Result<Json<FleetStatus>, ApiError> {
    authorize_admin(&state, &token, "bundle.status").await?;
    let service = require_bundle(&state)?;
    let now = state.clock().now();
    let status = service
        .fleet_status(now)
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
    Ok(Json(status))
}

/// `GET /api/v1/admin/ca/{id}/retirement` — whether a CA can be safely retired.
pub async fn retirement(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(id): Path<String>,
) -> Result<Json<RetirementAssessment>, ApiError> {
    authorize_admin(&state, &token, "ca.retirement").await?;
    let service = require_bundle(&state)?;
    let now = state.clock().now();
    let assessment = service.assess_retirement(&id, now).await?;
    Ok(Json(assessment))
}

/// `POST /api/v1/admin/ca/{id}/retire` — permanently retire a disabled CA.
///
/// Retirement deletes the key's private material and is irreversible. It is
/// refused when the safety assessment is `unsafe` unless `force=true` is set,
/// in which case a security warning and a `ca.retirement.forced` audit event
/// are emitted. A denied attempt records `ca.retirement.denied`; a completed
/// retirement records `ca.retired`. Keys are never silently removed.
pub async fn retire(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(id): Path<String>,
    request: Option<Json<RetireCaRequest>>,
) -> Result<Json<CaRecord>, ApiError> {
    let identity = authorize_admin(&state, &token, "ca.retire").await?;
    let ca = require_ca(&state)?;
    let service = require_bundle(&state)?;
    let force = request.map(|Json(r)| r.force).unwrap_or_default();

    let now = state.clock().now();
    let assessment = service.assess_retirement(&id, now).await?;

    if !assessment.safe && !force {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.login,
            key_id = %assessment.key_id,
            affected = assessment.affected_machines,
            "ca retirement denied: machines still depend on the key",
        );
        audit_retirement(
            &state,
            &identity,
            "ca.retirement.denied",
            &assessment,
            false,
        )
        .await?;
        return Err(ApiError::Conflict(format!(
            "retirement unsafe: {}",
            assessment.reason
        )));
    }

    if !assessment.safe {
        // Forced retirement over an unsafe assessment: loud and audited.
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.login,
            key_id = %assessment.key_id,
            affected = assessment.affected_machines,
            "ca retirement FORCED despite dependent machines",
        );
        audit_retirement(&state, &identity, "ca.retirement.forced", &assessment, true).await?;
    }

    let record = ca.retire(&id).await?;
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new("ca.retired", identity.login.clone())
                .with_subject(record.key_id.clone())
                .with_metadata(json!({
                    "id": record.id,
                    "fingerprint": record.fingerprint,
                    "forced": !assessment.safe,
                    "affected_machines": assessment.affected_machines,
                })),
        )
        .await?;
    Ok(Json(record))
}

/// The bundle distribution service, or a 500 if the server lacks a CA manager
/// or Bundle Signing Key.
fn require_bundle(state: &AppState) -> Result<BundleService, ApiError> {
    state.bundle_service().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!(
            "bundle distribution is not configured (missing CA manager or signing key)"
        ))
    })
}

/// Append a fail-closed audit event for a retirement decision.
async fn audit_retirement(
    state: &AppState,
    identity: &Identity,
    action: &str,
    assessment: &RetirementAssessment,
    forced: bool,
) -> Result<(), ApiError> {
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new(action, identity.login.clone())
                .with_subject(assessment.key_id.clone())
                .with_metadata(json!({
                    "id": assessment.id,
                    "affected_machines": assessment.affected_machines,
                    "oldest_generation": assessment.oldest_generation,
                    "latest_generation": assessment.latest_generation,
                    "forced": forced,
                    "reason": assessment.reason,
                })),
        )
        .await?;
    Ok(())
}

/// Resolve and authorize an admin caller (deny-by-default), auditing denials.
async fn authorize_admin(
    state: &AppState,
    token: &str,
    action: &str,
) -> Result<Identity, ApiError> {
    let identity = resolve_identity(state, token).await?;
    if let AuthzDecision::Deny { reason } = state.authz().authorize(&identity) {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.login,
            action = %action,
            reason = %reason,
            "ca admin action denied",
        );
        state
            .audit()
            .append_audit_event(
                NewAuditEntry::new("ca.admin_denied", identity.login.clone())
                    .with_subject(action.to_string())
                    .with_metadata(json!({ "reason": reason })),
            )
            .await?;
        return Err(AuthzError::Denied { reason }.into());
    }
    Ok(identity)
}

/// The CA manager, or a 500 if the server was started without one.
fn require_ca(state: &AppState) -> Result<Arc<CaManager>, ApiError> {
    state.ca().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("certificate authority is not configured"))
    })
}

/// Append a fail-closed audit event for a CA lifecycle change. The metadata
/// never includes key material or passphrases.
async fn audit_lifecycle(
    state: &AppState,
    identity: &Identity,
    action: &str,
    record: &CaRecord,
) -> Result<(), ApiError> {
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new(action, identity.login.clone())
                .with_subject(record.key_id.clone())
                .with_metadata(json!({
                    "id": record.id,
                    "fingerprint": record.fingerprint,
                    "enabled": record.enabled,
                })),
        )
        .await?;
    Ok(())
}
