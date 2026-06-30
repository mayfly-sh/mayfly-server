//! Fleet rollout console admin API (013D / ADR-0025).
//!
//! Read-only operator endpoints that make the CLI the rollout console:
//!
//! - `GET /api/v1/admin/rollout`             — headline status (progress/ETA/health).
//! - `GET /api/v1/admin/rollout/generations` — per-generation machine population.
//! - `GET /api/v1/admin/rollout/machines`    — per-machine rollout view (filterable).
//! - `GET /api/v1/admin/rollout/stuck`       — stuck machines + remediation.
//! - `GET /api/v1/admin/rollout/health`      — rollout health score + reasons.
//! - `GET /api/v1/admin/rollout/explain`     — categorized reasons for incompleteness.
//! - `GET /api/v1/admin/rollout/timeline`    — recent bundle rollout events.
//! - `GET /api/v1/admin/rollout/history`     — generation adoption history.
//!
//! Every endpoint authenticates a Bearer token and authorizes it
//! deny-by-default through the shared [`crate::routes::ops::authorize_admin`].
//! These are **reads**: like the 013C operational console they are
//! authorization-gated but **not** audited (the CLI polls them in `--watch`),
//! and only an authorization denial appends a fail-closed audit entry. No
//! endpoint returns secrets.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::{Extension, Json};
use serde::Deserialize;

use crate::errors::ApiError;
use crate::request_id::RequestId;
use crate::rollout::models::{GenerationsResponse, MachinesResponse};
use crate::rollout::{
    RolloutExplanation, RolloutHealth, RolloutHistory, RolloutService, RolloutStatus,
    RolloutTimeline, StuckReport, TIMELINE_DEFAULT_LIMIT,
};
use crate::routes::auth::BearerToken;
use crate::routes::ops::authorize_admin;
use crate::state::AppState;

/// Authorize the caller and load a rollout snapshot.
async fn load(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &RequestId,
    token: &str,
    action: &str,
) -> Result<RolloutService, ApiError> {
    authorize_admin(state, headers, request_id, token, action).await?;
    let configured = state.bundle_service().is_some();
    let now = state.clock().now();
    let svc = RolloutService::load(
        state.db().clone(),
        state.ca(),
        configured,
        &state.audit(),
        now,
    )
    .await?;
    Ok(svc)
}

/// `GET /api/v1/admin/rollout` — headline status.
pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<RolloutStatus>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.status").await?;
    Ok(Json(svc.status()))
}

/// `GET /api/v1/admin/rollout/generations` — per-generation population.
pub async fn generations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<GenerationsResponse>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.generations").await?;
    let status = svc.status();
    Ok(Json(GenerationsResponse {
        latest_generation: status.latest_generation,
        generations: status.generations,
    }))
}

/// Query parameters for the per-machine rollout view.
#[derive(Debug, Default, Deserialize)]
pub struct MachinesParams {
    /// `all` (default) | `current` | `lagging` | `stuck`.
    pub state: Option<String>,
    /// Restrict to machines on this synced generation.
    pub generation: Option<i64>,
}

/// `GET /api/v1/admin/rollout/machines` — per-machine rollout view.
pub async fn machines(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<MachinesParams>,
    BearerToken(token): BearerToken,
) -> Result<Json<MachinesResponse>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.machines").await?;
    let selector = params
        .state
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("all")
        .to_lowercase();
    match selector.as_str() {
        "all" | "current" | "lagging" | "stuck" => {}
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown state '{other}' (want all|current|lagging|stuck)"
            )))
        }
    }
    let machines = svc.machines_filtered(&selector, params.generation);
    Ok(Json(MachinesResponse {
        count: machines.len(),
        machines,
    }))
}

/// `GET /api/v1/admin/rollout/stuck` — stuck machines + remediation.
pub async fn stuck(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<StuckReport>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.stuck").await?;
    Ok(Json(svc.stuck()))
}

/// `GET /api/v1/admin/rollout/health` — rollout health score.
pub async fn health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<RolloutHealth>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.health").await?;
    Ok(Json(svc.health()))
}

/// `GET /api/v1/admin/rollout/explain` — categorized incompleteness reasons.
pub async fn explain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<RolloutExplanation>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.explain").await?;
    Ok(Json(svc.explain()))
}

/// Query parameters for the timeline.
#[derive(Debug, Default, Deserialize)]
pub struct TimelineParams {
    /// Maximum events to return (default 50, max 500).
    pub limit: Option<i64>,
}

/// `GET /api/v1/admin/rollout/timeline` — recent bundle rollout events.
pub async fn timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<TimelineParams>,
    BearerToken(token): BearerToken,
) -> Result<Json<RolloutTimeline>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.timeline").await?;
    let limit = params.limit.unwrap_or(TIMELINE_DEFAULT_LIMIT);
    let timeline = svc.timeline(&state.audit(), limit).await?;
    Ok(Json(timeline))
}

/// `GET /api/v1/admin/rollout/history` — generation adoption history.
pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<RolloutHistory>, ApiError> {
    let svc = load(&state, &headers, &request_id, &token, "rollout.history").await?;
    let history = svc.history(&state.audit()).await?;
    Ok(Json(history))
}
