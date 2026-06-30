//! Machine administration admin API.
//!
//! - `GET    /api/v1/admin/machines`                    — list machines (filterable).
//! - `GET    /api/v1/admin/machines/{id}`               — one machine's detail.
//! - `POST   /api/v1/admin/machines/{id}/approve`       — pending → active.
//! - `POST   /api/v1/admin/machines/{id}/disable`       — active → disabled.
//! - `POST   /api/v1/admin/machines/{id}/enable`        — disabled → active.
//! - `POST   /api/v1/admin/machines/{id}/revoke`        — → revoked.
//! - `DELETE /api/v1/admin/machines/{id}`               — delete the row.
//! - `POST   /api/v1/admin/machines/{id}/reenroll`      — delete + mint a token.
//! - `POST   /api/v1/admin/machines/{id}/rotate-identity` — delete + mint a token.
//!
//! Every endpoint authenticates a Bearer token through the provider abstraction
//! and authorizes it with the same deny-by-default policy as the CA admin API.
//! Reads (`list`/`get`) are intentionally **not** audited (the CLI polls them in
//! `--watch`, which would flood the hash-chained log); every **mutation** and
//! every **denial** appends a fail-closed audit entry recording the operator
//! identity and the privacy-preserving client context (ADR-0022). Disable /
//! revoke / delete take effect on the agent's next signed request because
//! `agentauth` rejects any non-`Active` machine.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit::{NewAuditEntry, RequestAuditContext};
use crate::authz::{AuthzDecision, AuthzError, Identity};
use crate::errors::ApiError;
use crate::machines::{
    EnrollmentService, LivenessStatus, Machine, MachineAdminService, MachineFilter, MachineStatus,
    MachineView,
};
use crate::request_id::RequestId;
use crate::routes::admin::MintEnrollmentTokenResponse;
use crate::routes::auth::{resolve_identity, BearerToken};
use crate::state::AppState;

/// Default lifetime of an enrollment token minted by re-enroll / rotate-identity.
const REENROLL_TOKEN_TTL_SECONDS: i64 = 3600;

/// Query parameters for `GET /api/v1/admin/machines`.
///
/// All optional; unknown/blank values are ignored. `status` and `liveness` are
/// validated against the known enum values and rejected with `400` otherwise.
#[derive(Debug, Default, Deserialize)]
pub struct MachineListQuery {
    /// Lifecycle status: `pending`/`active`/`disabled`/`revoked`.
    pub status: Option<String>,
    /// Derived liveness: `online`/`stale`/`offline`.
    pub liveness: Option<String>,
    /// Case-insensitive hostname substring.
    pub hostname: Option<String>,
    /// Current OR synced generation equals this value.
    pub generation: Option<i64>,
    /// Operating system (case-insensitive exact).
    pub os: Option<String>,
    /// Architecture (case-insensitive exact).
    pub arch: Option<String>,
    /// Agent version (case-insensitive exact).
    pub agent_version: Option<String>,
}

impl MachineListQuery {
    /// Convert the raw query into a typed [`MachineFilter`], validating enums.
    fn into_filter(self) -> Result<MachineFilter, ApiError> {
        let status = parse_opt(self.status, |v| {
            MachineStatus::from_db_str(&v.to_lowercase())
                .ok_or_else(|| ApiError::BadRequest(format!("unknown status '{v}'")))
        })?;
        let liveness = parse_opt(self.liveness, |v| {
            parse_liveness(v)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown liveness '{v}'")))
        })?;
        Ok(MachineFilter {
            status,
            liveness,
            hostname: non_empty(self.hostname),
            generation: self.generation,
            os: non_empty(self.os),
            arch: non_empty(self.arch),
            agent_version: non_empty(self.agent_version),
        })
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_opt<T>(
    value: Option<String>,
    parse: impl Fn(&str) -> Result<T, ApiError>,
) -> Result<Option<T>, ApiError> {
    match non_empty(value) {
        None => Ok(None),
        Some(v) => parse(&v).map(Some),
    }
}

fn parse_liveness(value: &str) -> Option<LivenessStatus> {
    match value.to_lowercase().as_str() {
        "online" => Some(LivenessStatus::Online),
        "stale" => Some(LivenessStatus::Stale),
        "offline" => Some(LivenessStatus::Offline),
        _ => None,
    }
}

/// Response body for `DELETE /api/v1/admin/machines/{id}`.
#[derive(Debug, Clone, Serialize)]
pub struct DeleteMachineResponse {
    /// Always `true` on success.
    pub deleted: bool,
    /// The deleted machine's id.
    pub machine_id: String,
    /// The deleted machine's hostname (freed for re-enrollment).
    pub hostname: String,
}

/// `GET /api/v1/admin/machines` — list machines with optional filters.
pub async fn list_machines(
    State(state): State<AppState>,
    Query(query): Query<MachineListQuery>,
    BearerToken(token): BearerToken,
) -> Result<Json<Vec<MachineView>>, ApiError> {
    authorize_admin(&state, &token, "machine.list").await?;
    let filter = query.into_filter()?;
    let now = state.clock().now();
    let service = MachineAdminService::sqlite(state.db().clone());
    let views = service
        .list(now, latest_generation(&state), &filter)
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
    Ok(Json(views))
}

/// `GET /api/v1/admin/machines/{id}` — one machine's detail.
pub async fn get_machine(
    State(state): State<AppState>,
    Path(id): Path<String>,
    BearerToken(token): BearerToken,
) -> Result<Json<MachineView>, ApiError> {
    authorize_admin(&state, &token, "machine.get").await?;
    let now = state.clock().now();
    let service = MachineAdminService::sqlite(state.db().clone());
    service
        .get(now, latest_generation(&state), &id)
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("machine '{id}' was not found")))
}

/// `POST /api/v1/admin/machines/{id}/approve`.
pub async fn approve(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    request_id: Extension<RequestId>,
    token: BearerToken,
) -> Result<Json<MachineView>, ApiError> {
    set_lifecycle(
        state,
        path,
        headers,
        request_id,
        token,
        MachineStatus::Active,
        "machine.approved",
    )
    .await
}

/// `POST /api/v1/admin/machines/{id}/disable`.
pub async fn disable(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    request_id: Extension<RequestId>,
    token: BearerToken,
) -> Result<Json<MachineView>, ApiError> {
    set_lifecycle(
        state,
        path,
        headers,
        request_id,
        token,
        MachineStatus::Disabled,
        "machine.disabled",
    )
    .await
}

/// `POST /api/v1/admin/machines/{id}/enable`.
pub async fn enable(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    request_id: Extension<RequestId>,
    token: BearerToken,
) -> Result<Json<MachineView>, ApiError> {
    set_lifecycle(
        state,
        path,
        headers,
        request_id,
        token,
        MachineStatus::Active,
        "machine.enabled",
    )
    .await
}

/// `POST /api/v1/admin/machines/{id}/revoke`.
pub async fn revoke(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    request_id: Extension<RequestId>,
    token: BearerToken,
) -> Result<Json<MachineView>, ApiError> {
    set_lifecycle(
        state,
        path,
        headers,
        request_id,
        token,
        MachineStatus::Revoked,
        "machine.revoked",
    )
    .await
}

/// Shared lifecycle mutation: authorize → set status → audit → return view.
async fn set_lifecycle(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    target: MachineStatus,
    action: &str,
) -> Result<Json<MachineView>, ApiError> {
    let identity = authorize_admin(&state, &token, action).await?;
    let now = state.clock().now();
    let service = MachineAdminService::sqlite(state.db().clone());
    let machine = service.set_status(&id, target, now).await?;

    audit_machine(
        &state,
        &identity,
        &headers,
        &request_id,
        action,
        &machine,
        None,
    )
    .await?;
    Ok(Json(MachineView::from_machine(
        &machine,
        now,
        latest_generation(&state),
    )))
}

/// `DELETE /api/v1/admin/machines/{id}` — permanently remove a machine.
pub async fn delete_machine(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<DeleteMachineResponse>, ApiError> {
    let identity = authorize_admin(&state, &token, "machine.delete").await?;
    let service = MachineAdminService::sqlite(state.db().clone());
    let machine = service.delete(&id).await?;

    audit_machine(
        &state,
        &identity,
        &headers,
        &request_id,
        "machine.deleted",
        &machine,
        None,
    )
    .await?;
    Ok(Json(DeleteMachineResponse {
        deleted: true,
        machine_id: machine.machine_id.clone(),
        hostname: machine.hostname.clone(),
    }))
}

/// `POST /api/v1/admin/machines/{id}/reenroll`.
pub async fn reenroll(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    request_id: Extension<RequestId>,
    token: BearerToken,
) -> Result<(StatusCode, Json<MintEnrollmentTokenResponse>), ApiError> {
    reissue_identity(
        state,
        path,
        headers,
        request_id,
        token,
        "machine.reenroll_requested",
    )
    .await
}

/// `POST /api/v1/admin/machines/{id}/rotate-identity`.
pub async fn rotate_identity(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    request_id: Extension<RequestId>,
    token: BearerToken,
) -> Result<(StatusCode, Json<MintEnrollmentTokenResponse>), ApiError> {
    reissue_identity(
        state,
        path,
        headers,
        request_id,
        token,
        "machine.identity_rotation_requested",
    )
    .await
}

/// Shared re-enroll / rotate-identity: delete the old machine (freeing its
/// hostname + key), mint a fresh single-use enrollment token, audit, return it.
///
/// The host re-enrolls out-of-band and generates a *new* keypair at enrollment,
/// which is exactly an identity rotation. The old identity is dead immediately
/// (the row is gone, so its signed requests fail as an unknown machine).
async fn reissue_identity(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
    action: &str,
) -> Result<(StatusCode, Json<MintEnrollmentTokenResponse>), ApiError> {
    let identity = authorize_admin(&state, &token, action).await?;

    // Enrollment depends on a configured CA (the enroll response embeds the
    // server identity), so resolve it before destroying the old machine.
    let ca = state.ca().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("certificate authority is not configured"))
    })?;
    let server_identity = ca
        .primary_public_key()
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;

    let service = MachineAdminService::sqlite(state.db().clone());
    let old = service.delete(&id).await?;

    let enrollment =
        EnrollmentService::sqlite(state.db().clone(), state.clock_arc(), server_identity);
    let issued = enrollment
        .create_enrollment_token(
            identity.username.clone(),
            TimeDelta::seconds(REENROLL_TOKEN_TTL_SECONDS),
            true,
        )
        .await
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;

    audit_machine(
        &state,
        &identity,
        &headers,
        &request_id,
        action,
        &old,
        Some(json!({
            "enrollment_token_id": issued.record.id,
            "token_expires_at": issued.record.expires_at.to_rfc3339(),
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

/// Current CA generation as an `i64`, or `None` when no CA is configured.
fn latest_generation(state: &AppState) -> Option<i64> {
    state.ca().map(|ca| i64::from(ca.generation()))
}

/// Append a fail-closed audit entry for a machine mutation, recording the
/// operator identity, the machine, and the privacy-preserving client context.
/// Never logs tokens or key material.
async fn audit_machine(
    state: &AppState,
    identity: &Identity,
    headers: &HeaderMap,
    request_id: &RequestId,
    action: &str,
    machine: &Machine,
    extra: Option<serde_json::Value>,
) -> Result<(), ApiError> {
    let client =
        RequestAuditContext::from_headers(headers, Some(request_id.as_str()), state.clock().now())
            .with_provider(identity.provider.clone());
    let mut metadata = json!({
        "hostname": machine.hostname,
        "status": machine.status.as_str(),
        "agent_version": machine.agent_version,
        "provider": identity.provider,
        "subject": identity.subject,
        "client": client.to_value(),
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
                .with_subject(machine.machine_id.clone())
                .with_metadata(metadata),
        )
        .await?;
    Ok(())
}

/// Resolve and authorize an admin caller (deny-by-default), auditing denials.
///
/// Mirrors the CA admin authorization but records a machine-specific denial
/// event. Reads pass through here too (so unauthorized listing is denied and
/// audited) but successful reads are not otherwise audited.
async fn authorize_admin(
    state: &AppState,
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
            "machine admin action denied",
        );
        state
            .audit()
            .append_audit_event(
                NewAuditEntry::new("machine.admin_denied", identity.username.clone())
                    .with_subject(action.to_string())
                    .with_metadata(json!({ "reason": reason })),
            )
            .await?;
        return Err(AuthzError::Denied { reason }.into());
    }
    Ok(identity)
}
