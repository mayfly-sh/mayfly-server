//! Operator-facing server registry endpoint.
//!
//! - `GET /api/v1/servers` — list enrolled machines with derived liveness.
//!
//! Authentication is a Bearer token resolved through the provider abstraction;
//! authorization is the same deny-by-default allowlist used for certificate
//! issuance. Liveness status is always derived from `last_seen` server-side and
//! never trusted from a client.

use axum::extract::{Query, State};
use axum::Json;

use crate::authz::{AuthzDecision, AuthzError};
use crate::errors::ApiError;
use crate::machines::protocol::DEFAULT_LIST_LIMIT;
use crate::machines::{RegistryService, ServerSummary};
use crate::routes::auth::{resolve_identity, BearerToken, ProviderQuery};
use crate::state::AppState;

/// `GET /api/v1/servers` — list machines (requires an authorized token).
pub async fn list_servers(
    State(state): State<AppState>,
    Query(query): Query<ProviderQuery>,
    BearerToken(token): BearerToken,
) -> Result<Json<Vec<ServerSummary>>, ApiError> {
    // 1. Resolve identity through the selected provider (provider-agnostic).
    let identity = resolve_identity(&state, query.provider.as_deref(), &token).await?;

    // 2. Authorize (deny-by-default).
    if let AuthzDecision::Deny { reason } = state.authz().authorize(&identity) {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.username,
            provider = %identity.provider,
            reason = %reason,
            "server listing denied",
        );
        return Err(AuthzError::Denied { reason }.into());
    }

    // 3. List with server-derived liveness.
    let now = state.clock().now();
    let service = RegistryService::sqlite(state.db().clone());
    let servers = service.list_servers(now, DEFAULT_LIST_LIMIT).await?;
    Ok(Json(servers))
}
