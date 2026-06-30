//! CA management admin API.
//!
//! - `POST   /api/v1/admin/ca/generate`        — generate a new encrypted Ed25519 CA.
//! - `POST   /api/v1/admin/ca/import`          — import an existing encrypted CA key.
//! - `POST   /api/v1/admin/ca/rotate`          — guided rotation: generate a new CA + report rollout.
//! - `GET    /api/v1/admin/ca`                 — list all CA metadata (as `CaView`).
//! - `GET    /api/v1/admin/ca/stats`           — aggregate signing statistics.
//! - `GET    /api/v1/admin/ca/bundle`          — the current public trust bundle (active CAs).
//! - `GET    /api/v1/admin/ca/{id}`            — detailed metadata for one CA (`CaView`).
//! - `GET    /api/v1/admin/ca/{id}/public-key` — export one CA's public key + fingerprint.
//! - `PATCH  /api/v1/admin/ca/{id}`            — enable / disable / rename a CA.
//! - `POST   /api/v1/admin/ca/{id}/enable`     — enable a CA.
//! - `POST   /api/v1/admin/ca/{id}/disable`    — disable a CA.
//! - `GET    /api/v1/admin/ca/{id}/retirement` — retirement-safety assessment.
//! - `POST   /api/v1/admin/ca/{id}/retire`     — retire a disabled CA (keeps row, drops key).
//! - `DELETE /api/v1/admin/ca/{id}`            — delete an unused (disabled, safe) CA.
//! - `GET    /api/v1/admin/bundle/status`      — fleet rollout visibility.
//!
//! Every endpoint authenticates a Bearer token through the provider abstraction
//! and authorizes it with deny-by-default authorization. Reads
//! (list/show/stats/bundle/public-key/retirement/status) are authorization-gated
//! but **not** audited (the CLI polls them in `--watch`, which would flood the
//! hash-chained log). Every **mutation** and every **denial** appends a
//! fail-closed audit entry recording the operator identity and the
//! privacy-preserving client context (ADR-0023). Private key material is never
//! returned, and passphrases are never logged or audited.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit::{NewAuditEntry, RequestAuditContext};
use crate::authz::{AuthzDecision, AuthzError, Identity};
use crate::bundle::{BundleService, FleetStatus, RetirementAssessment};
use crate::ca::{
    CaManager, CaPublicKeyEntry, CaRecord, CaStats, CaView, PublicBundle, RotationResult,
};
use crate::errors::ApiError;
use crate::machines::EnrollmentService;
use crate::request_id::RequestId;
use crate::routes::auth::{resolve_identity, BearerToken};
use crate::state::AppState;

/// Default enrollment-token lifetime when the request omits `ttl_seconds`.
const DEFAULT_ENROLLMENT_TOKEN_TTL_SECONDS: u32 = 3600;
/// Lower bound on a minted enrollment token's lifetime (1 minute).
const MIN_ENROLLMENT_TOKEN_TTL_SECONDS: u32 = 60;
/// Upper bound on a minted enrollment token's lifetime (24 hours).
const MAX_ENROLLMENT_TOKEN_TTL_SECONDS: u32 = 86_400;

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

/// Request body for `POST /api/v1/admin/ca/rotate`.
#[derive(Debug, Clone, Deserialize)]
pub struct RotateCaRequest {
    /// Operator-assigned id for the new CA. When absent, a timestamped id is
    /// generated.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Passphrase protecting the new key at rest. Must match the storage
    /// passphrase. Never logged.
    pub passphrase: String,
}

/// `POST /api/v1/admin/ca/generate`
pub async fn generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    Json(request): Json<GenerateCaRequest>,
) -> Result<(StatusCode, Json<CaView>), ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.generate").await?;
    let ca = require_ca(&state)?;

    let record = ca
        .generate(request.key_id.trim(), &request.passphrase)
        .await?;
    audit_ca(
        &state,
        &identity,
        &headers,
        &request_id,
        "ca.generated",
        &record,
        None,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(view(&state, &record))))
}

/// `POST /api/v1/admin/ca/import`
pub async fn import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    Json(request): Json<ImportCaRequest>,
) -> Result<(StatusCode, Json<CaView>), ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.import").await?;
    let ca = require_ca(&state)?;

    let record = ca
        .import(
            request.key_id.trim(),
            &request.private_key,
            &request.passphrase,
        )
        .await?;
    audit_ca(
        &state,
        &identity,
        &headers,
        &request_id,
        "ca.imported",
        &record,
        None,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(view(&state, &record))))
}

/// `GET /api/v1/admin/ca`
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<Vec<CaView>>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ca.list").await?;
    let ca = require_ca(&state)?;
    let now = state.clock().now();
    let generation = ca.generation();
    let views = ca
        .list()
        .iter()
        .map(|r| CaView::from_record(r, generation, now))
        .collect();
    Ok(Json(views))
}

/// `GET /api/v1/admin/ca/stats`
pub async fn stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<CaStats>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ca.stats").await?;
    let ca = require_ca(&state)?;
    let stats = CaStats::from_records(&ca.list(), ca.generation(), ca.bundle_fingerprint());
    Ok(Json(stats))
}

/// `GET /api/v1/admin/ca/bundle` — the current public trust bundle (active CAs).
pub async fn public_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<PublicBundle>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ca.bundle").await?;
    let ca = require_ca(&state)?;
    Ok(Json(ca.get_public_bundle()))
}

/// `GET /api/v1/admin/ca/{id}`
pub async fn get_one(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<CaView>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ca.get").await?;
    let ca = require_ca(&state)?;
    ca.get(&id)
        .map(|r| Json(view(&state, &r)))
        .ok_or_else(|| ApiError::NotFound(format!("ca '{id}' was not found")))
}

/// `GET /api/v1/admin/ca/{id}/public-key` — export one CA's public key.
pub async fn export_public_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<CaPublicKeyEntry>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ca.export").await?;
    let ca = require_ca(&state)?;
    ca.get(&id)
        .map(|r| {
            Json(CaPublicKeyEntry {
                key_id: r.key_id,
                public_key: r.public_key,
                fingerprint: r.fingerprint,
            })
        })
        .ok_or_else(|| ApiError::NotFound(format!("ca '{id}' was not found")))
}

/// `PATCH /api/v1/admin/ca/{id}`
pub async fn patch(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    Json(request): Json<PatchCaRequest>,
) -> Result<Json<CaView>, ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.patch").await?;
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
            audit_ca(
                &state,
                &identity,
                &headers,
                &request_id,
                "ca.renamed",
                &record,
                None,
            )
            .await?;
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
            audit_ca(
                &state,
                &identity,
                &headers,
                &request_id,
                action,
                &record,
                None,
            )
            .await?;
        }
    }

    Ok(Json(view(&state, &record)))
}

/// `POST /api/v1/admin/ca/{id}/enable`
pub async fn enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<CaView>, ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.enable").await?;
    let ca = require_ca(&state)?;
    let before = ca
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("ca '{id}' was not found")))?;
    let record = ca.enable(&id).await?;
    if !before.enabled {
        audit_ca(
            &state,
            &identity,
            &headers,
            &request_id,
            "ca.enabled",
            &record,
            None,
        )
        .await?;
    }
    Ok(Json(view(&state, &record)))
}

/// `POST /api/v1/admin/ca/{id}/disable`
pub async fn disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<CaView>, ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.disable").await?;
    let ca = require_ca(&state)?;
    let before = ca
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("ca '{id}' was not found")))?;
    let record = ca.disable(&id).await?;
    if before.enabled {
        audit_ca(
            &state,
            &identity,
            &headers,
            &request_id,
            "ca.disabled",
            &record,
            None,
        )
        .await?;
    }
    Ok(Json(view(&state, &record)))
}

/// `POST /api/v1/admin/ca/rotate` — guided rotation step.
///
/// Generates a new enabled CA (bumping the generation so the fleet starts
/// trusting it) and returns the rollout state needed to finish the rotation
/// safely. It deliberately does **not** disable or retire the predecessor — the
/// old CA must keep signing/validating until the fleet has synced the new
/// generation (ADR-0023). Completes with `disable` + `retire` once converged.
pub async fn rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    Json(request): Json<RotateCaRequest>,
) -> Result<(StatusCode, Json<RotationResult>), ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.rotate").await?;
    let ca = require_ca(&state)?;
    let service = require_bundle(&state)?;
    let now = state.clock().now();

    // Snapshot the active set *before* adding the new CA.
    let previous_active = ca.active_keys();

    let key_id = match request
        .key_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(k) => k.to_string(),
        None => format!("mayfly-ca-{}", now.format("%Y%m%dT%H%M%SZ")),
    };

    let new_record = ca.generate(&key_id, &request.passphrase).await?;
    let generation = ca.generation();

    audit_ca(
        &state,
        &identity,
        &headers,
        &request_id,
        "ca.rotated",
        &new_record,
        Some(json!({
            "generation": generation,
            "previous_active": previous_active
                .iter()
                .map(|r| r.key_id.clone())
                .collect::<Vec<_>>(),
        })),
    )
    .await?;

    let rollout = service
        .fleet_status(now)
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;

    let on_latest: i64 = rollout
        .generations
        .iter()
        .filter(|g| g.generation == i64::from(rollout.latest_generation))
        .map(|g| g.count)
        .sum();
    let behind = (rollout.total_machines - on_latest).max(0);

    let mut warnings = vec![format!(
        "New CA '{}' is active at generation {}. The previous CA(s) remain active during rollout.",
        new_record.key_id, generation
    )];
    if !previous_active.is_empty() {
        warnings.push(
            "Do NOT disable or retire the previous CA(s) until the fleet reaches 100% on the new \
             generation — hosts that have not yet synced would lose trust."
                .to_string(),
        );
    }
    if behind > 0 {
        warnings.push(format!(
            "{behind} machine(s) are not yet on generation {generation} ({:.1}% converged).",
            rollout.rollout_percentage
        ));
    }

    let new_ca = view(&state, &new_record);
    let previous_active = previous_active
        .iter()
        .map(|r| CaView::from_record(r, generation, now))
        .collect();

    Ok((
        StatusCode::CREATED,
        Json(RotationResult {
            new_ca,
            previous_active,
            rollout,
            warnings,
        }),
    ))
}

/// Query parameters for `DELETE /api/v1/admin/ca/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DeleteCaParams {
    /// When `true`, delete even if machines still depend on the key.
    #[serde(default)]
    pub force: bool,
}

/// Response body for `DELETE /api/v1/admin/ca/{id}`.
#[derive(Debug, Clone, Serialize)]
pub struct DeleteCaResponse {
    /// Always `true` on success.
    pub deleted: bool,
    /// The deleted CA's id.
    pub id: String,
    /// The deleted CA's operator-assigned key id.
    pub key_id: String,
}

/// `DELETE /api/v1/admin/ca/{id}` — permanently delete an unused CA.
///
/// Unlike retirement, no metadata row is kept. The CA must be disabled (an
/// enabled CA is refused — disable it first) and, like retirement, no machine
/// may still depend on the key unless `force=true`. A denied attempt records
/// `ca.delete.denied`; a forced delete records `ca.delete.forced`; a completed
/// delete records `ca.deleted`.
pub async fn delete_ca(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<DeleteCaParams>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<DeleteCaResponse>, ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.delete").await?;
    let ca = require_ca(&state)?;
    let service = require_bundle(&state)?;

    let record = ca
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("ca '{id}' was not found")))?;

    // An enabled CA is never deletable; surface the clear conflict before any
    // safety assessment (which would also report it unsafe).
    if record.enabled {
        return Err(ApiError::Conflict(format!(
            "cannot delete ca '{}': it is still active (disable it first)",
            record.key_id
        )));
    }

    let now = state.clock().now();
    let assessment = service.assess_retirement(&id, now).await?;

    if !assessment.safe && !params.force {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.username,
            key_id = %assessment.key_id,
            affected = assessment.affected_machines,
            "ca delete denied: machines still depend on the key",
        );
        audit_retirement(
            &state,
            &identity,
            &headers,
            &request_id,
            "ca.delete.denied",
            &assessment,
            false,
        )
        .await?;
        return Err(ApiError::Conflict(format!(
            "delete unsafe: {}",
            assessment.reason
        )));
    }

    if !assessment.safe {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.username,
            key_id = %assessment.key_id,
            affected = assessment.affected_machines,
            "ca delete FORCED despite dependent machines",
        );
        audit_retirement(
            &state,
            &identity,
            &headers,
            &request_id,
            "ca.delete.forced",
            &assessment,
            true,
        )
        .await?;
    }

    let deleted = ca.delete(&id).await?;
    audit_ca(
        &state,
        &identity,
        &headers,
        &request_id,
        "ca.deleted",
        &deleted,
        Some(json!({ "forced": !assessment.safe })),
    )
    .await?;
    Ok(Json(DeleteCaResponse {
        deleted: true,
        id: deleted.id,
        key_id: deleted.key_id,
    }))
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
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<FleetStatus>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "bundle.status").await?;
    let service = require_bundle(&state)?;
    let now = state.clock().now();
    let status = service
        .fleet_status(now)
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
    Ok(Json(status))
}

/// Request body for `POST /api/v1/admin/machines/enrollment-tokens`.
///
/// Both fields are optional: `ttl_seconds` defaults to
/// [`DEFAULT_ENROLLMENT_TOKEN_TTL_SECONDS`] (and is clamped to
/// `[MIN, MAX]`), and `single_use` defaults to `true`.
#[derive(Debug, Clone, Deserialize)]
pub struct MintEnrollmentTokenRequest {
    /// Requested token lifetime in seconds. `0`/absent selects the default;
    /// out-of-range values are clamped.
    #[serde(default)]
    pub ttl_seconds: u32,
    /// Whether the token may be redeemed only once. Defaults to `true`.
    #[serde(default = "default_single_use")]
    pub single_use: bool,
}

fn default_single_use() -> bool {
    true
}

impl Default for MintEnrollmentTokenRequest {
    fn default() -> Self {
        Self {
            ttl_seconds: 0,
            single_use: true,
        }
    }
}

/// Response body for a minted enrollment token.
///
/// The plaintext `token` is returned **exactly once** and is never persisted or
/// audited; only its SHA-256 hash is stored server-side. Deliver it to the host
/// being enrolled and then discard it.
#[derive(Debug, Clone, Serialize)]
pub struct MintEnrollmentTokenResponse {
    /// The one-time plaintext enrollment token (`mf_enroll_…`).
    pub token: String,
    /// Opaque identifier of the stored token record (safe to log).
    pub id: String,
    /// RFC 3339 expiry timestamp.
    pub expires_at: String,
    /// Whether the token is single-use.
    pub single_use: bool,
}

/// `POST /api/v1/admin/machines/enrollment-tokens` — mint an enrollment token.
///
/// Authenticated and authorized exactly like the CA admin API (Bearer +
/// deny-by-default). Delegates token generation to the enrollment service, which
/// persists only the SHA-256 hash. The plaintext is returned once in the
/// response and is never logged or audited.
pub async fn mint_enrollment_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    request: Option<Json<MintEnrollmentTokenRequest>>,
) -> Result<(StatusCode, Json<MintEnrollmentTokenResponse>), ApiError> {
    let identity = authorize_admin(
        &state,
        &headers,
        &request_id,
        &token,
        "machine.enrollment_token.mint",
    )
    .await?;

    // Enrollment depends on a configured CA (the enroll response embeds the
    // server identity); keep minting consistent with that prerequisite so a
    // token is never issued for a server that cannot enroll.
    let ca = require_ca(&state)?;
    let server_identity = ca
        .primary_public_key()
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;

    let request = request.map(|Json(r)| r).unwrap_or_default();
    let ttl_seconds = clamp_enrollment_token_ttl(request.ttl_seconds);
    let ttl = TimeDelta::seconds(i64::from(ttl_seconds));

    let service = EnrollmentService::sqlite(state.db().clone(), state.clock_arc(), server_identity);
    let issued = service
        .create_enrollment_token(identity.username.clone(), ttl, request.single_use)
        .await
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;

    // Audit the mint (fail-closed). The record id and metadata are non-secret;
    // the plaintext token is NEVER audited or logged.
    let client =
        RequestAuditContext::from_headers(&headers, Some(request_id.as_str()), state.clock().now())
            .with_provider(identity.provider.clone());
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new("machine.enrollment_token.minted", identity.username.clone())
                .with_subject(issued.record.id.clone())
                .with_metadata(json!({
                    "expires_at": issued.record.expires_at.to_rfc3339(),
                    "single_use": issued.record.single_use,
                    "ttl_seconds": ttl_seconds,
                    "client": client.to_value(),
                })),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(MintEnrollmentTokenResponse {
            token: issued.plaintext,
            id: issued.record.id,
            expires_at: issued.record.expires_at.to_rfc3339(),
            single_use: issued.record.single_use,
        }),
    ))
}

/// Clamp a requested TTL into the accepted window, defaulting a `0` request.
fn clamp_enrollment_token_ttl(requested: u32) -> u32 {
    if requested == 0 {
        DEFAULT_ENROLLMENT_TOKEN_TTL_SECONDS
    } else {
        requested.clamp(
            MIN_ENROLLMENT_TOKEN_TTL_SECONDS,
            MAX_ENROLLMENT_TOKEN_TTL_SECONDS,
        )
    }
}

/// `GET /api/v1/admin/ca/{id}/retirement` — whether a CA can be safely retired.
pub async fn retirement(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<RetirementAssessment>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ca.retirement").await?;
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
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    request: Option<Json<RetireCaRequest>>,
) -> Result<Json<CaView>, ApiError> {
    let identity = authorize_admin(&state, &headers, &request_id, &token, "ca.retire").await?;
    let ca = require_ca(&state)?;
    let service = require_bundle(&state)?;
    let force = request.map(|Json(r)| r.force).unwrap_or_default();

    let now = state.clock().now();
    let assessment = service.assess_retirement(&id, now).await?;

    if !assessment.safe && !force {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.username,
            key_id = %assessment.key_id,
            affected = assessment.affected_machines,
            "ca retirement denied: machines still depend on the key",
        );
        audit_retirement(
            &state,
            &identity,
            &headers,
            &request_id,
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
            actor = %identity.username,
            key_id = %assessment.key_id,
            affected = assessment.affected_machines,
            "ca retirement FORCED despite dependent machines",
        );
        audit_retirement(
            &state,
            &identity,
            &headers,
            &request_id,
            "ca.retirement.forced",
            &assessment,
            true,
        )
        .await?;
    }

    let record = ca.retire(&id).await?;
    audit_ca(
        &state,
        &identity,
        &headers,
        &request_id,
        "ca.retired",
        &record,
        Some(json!({
            "forced": !assessment.safe,
            "affected_machines": assessment.affected_machines,
        })),
    )
    .await?;
    Ok(Json(view(&state, &record)))
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

/// Project a record into a [`CaView`] as of now with the current generation.
fn view(state: &AppState, record: &CaRecord) -> CaView {
    let generation = state.ca().map(|ca| ca.generation()).unwrap_or(0);
    CaView::from_record(record, generation, state.clock().now())
}

/// Build the privacy-preserving client-context block for an audit entry.
fn client_context(
    state: &AppState,
    identity: &Identity,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> serde_json::Value {
    RequestAuditContext::from_headers(headers, Some(request_id.as_str()), state.clock().now())
        .with_provider(identity.provider.clone())
        .to_value()
}

/// Append a fail-closed audit event for a retirement/delete decision.
async fn audit_retirement(
    state: &AppState,
    identity: &Identity,
    headers: &HeaderMap,
    request_id: &RequestId,
    action: &str,
    assessment: &RetirementAssessment,
    forced: bool,
) -> Result<(), ApiError> {
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new(action, identity.username.clone())
                .with_subject(assessment.key_id.clone())
                .with_metadata(json!({
                    "id": assessment.id,
                    "affected_machines": assessment.affected_machines,
                    "oldest_generation": assessment.oldest_generation,
                    "latest_generation": assessment.latest_generation,
                    "forced": forced,
                    "reason": assessment.reason,
                    "provider": identity.provider,
                    "subject": identity.subject,
                    "client": client_context(state, identity, headers, request_id),
                })),
        )
        .await?;
    Ok(())
}

/// Resolve and authorize an admin caller (deny-by-default), auditing denials
/// with operator identity + privacy-preserving client context.
async fn authorize_admin(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &RequestId,
    token: &str,
    action: &str,
) -> Result<Identity, ApiError> {
    let identity = resolve_identity(state, None, token).await?;
    if let AuthzDecision::Deny { reason } = state.authz().authorize(&identity) {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.username,
            action = %action,
            reason = %reason,
            "ca admin action denied",
        );
        state
            .audit()
            .append_audit_event(
                NewAuditEntry::new("ca.admin_denied", identity.username.clone())
                    .with_subject(action.to_string())
                    .with_metadata(json!({
                        "reason": reason,
                        "provider": identity.provider,
                        "subject": identity.subject,
                        "client": client_context(state, &identity, headers, request_id),
                    })),
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
/// never includes key material or passphrases; it records the operator identity
/// and the privacy-preserving client context (ADR-0023).
async fn audit_ca(
    state: &AppState,
    identity: &Identity,
    headers: &HeaderMap,
    request_id: &RequestId,
    action: &str,
    record: &CaRecord,
    extra: Option<serde_json::Value>,
) -> Result<(), ApiError> {
    let mut metadata = json!({
        "id": record.id,
        "fingerprint": record.fingerprint,
        "enabled": record.enabled,
        "provider": identity.provider,
        "subject": identity.subject,
        "client": client_context(state, identity, headers, request_id),
    });
    if let Some(extra) = extra {
        if let (Some(obj), Some(extra_obj)) = (metadata.as_object_mut(), extra.as_object()) {
            for (k, v) in extra_obj {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new(action, identity.username.clone())
                .with_subject(record.key_id.clone())
                .with_metadata(metadata),
        )
        .await?;
    Ok(())
}
