//! Operator-facing server registry endpoint.
//!
//! - `GET /api/v1/servers` — list enrolled machines with derived liveness.
//!
//! Authentication is a GitHub Bearer token; authorization is the same
//! deny-by-default allowlist used for certificate issuance. Liveness status is
//! always derived from `last_seen` server-side and never trusted from a client.

use axum::extract::State;
use axum::Json;

use crate::authz::{AuthzDecision, AuthzError, Identity};
use crate::errors::ApiError;
use crate::github::GitHubError;
use crate::machines::protocol::DEFAULT_LIST_LIMIT;
use crate::machines::{RegistryService, ServerSummary};
use crate::routes::auth::BearerToken;
use crate::state::AppState;

/// `GET /api/v1/servers` — list machines (requires an authorized GitHub token).
pub async fn list_servers(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> Result<Json<Vec<ServerSummary>>, ApiError> {
    let github = state.github();

    // 1. Resolve the GitHub identity from the bearer token.
    let user = github.get_user(&token).await?;

    let access = &state.config().access;
    let orgs = if access.allowed_orgs.is_empty() {
        Vec::new()
    } else {
        fetch_or_empty(github.get_user_orgs(&token).await, "orgs")
    };
    let teams = if access.allowed_teams.is_empty() {
        Vec::new()
    } else {
        fetch_or_empty(github.get_user_teams(&token).await, "teams")
    };

    let identity = Identity {
        login: user.login,
        github_id: user.id,
        orgs,
        teams,
    };

    // 2. Authorize (deny-by-default).
    if let AuthzDecision::Deny { reason } = state.authz().authorize(&identity) {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.login,
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

/// Use a successful org/team lookup, or treat a failure as "no memberships".
///
/// Authorization is deny-by-default, so failing closed here is safe.
fn fetch_or_empty(result: Result<Vec<String>, GitHubError>, what: &str) -> Vec<String> {
    match result {
        Ok(values) => values,
        Err(err) => {
            tracing::warn!(
                error = %err,
                membership = what,
                "failed to resolve GitHub membership; treating as none for authorization",
            );
            Vec::new()
        }
    }
}
