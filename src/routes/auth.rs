//! GitHub Device Flow authentication endpoints.
//!
//! - `POST /api/v1/auth/device/start` — begin the flow.
//! - `POST /api/v1/auth/device/poll`  — exchange a device code for a token.
//! - `GET  /api/v1/auth/whoami`       — resolve identity from a Bearer token.
//!
//! Handlers depend only on [`AppState`]'s injected [`crate::github::GitHubClient`]
//! and never touch HTTP/GitHub directly. Access tokens and device codes appear
//! only in request/response bodies and are never logged.

use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::Json;
use serde_json::json;

use crate::audit::NewAuditEntry;
use crate::authz::Identity;
use crate::errors::ApiError;
use crate::github::models::{DevicePollRequest, PollResponse, WhoamiResponse};
use crate::github::DeviceTokenOutcome;
use crate::state::AppState;

/// Maximum accepted length for a client-supplied `device_code`.
const MAX_DEVICE_CODE_LEN: usize = 256;

/// `POST /api/v1/auth/device/start` — begin the GitHub device flow.
pub async fn device_start(
    State(state): State<AppState>,
) -> Result<Json<crate::github::DeviceAuthorization>, ApiError> {
    let authorization = state.github().start_device_flow().await?;
    Ok(Json(authorization))
}

/// `POST /api/v1/auth/device/poll` — poll for the device-flow result.
///
/// The `device_code` is read from the JSON body only. Pending/slow_down/
/// expired/denied outcomes are not audited; only a successful authorization is.
pub async fn device_poll(
    State(state): State<AppState>,
    Json(request): Json<DevicePollRequest>,
) -> Result<Json<PollResponse>, ApiError> {
    let device_code = request.device_code.trim();
    if device_code.is_empty() || device_code.len() > MAX_DEVICE_CODE_LEN {
        return Err(ApiError::BadRequest("device_code is required".to_string()));
    }

    match state.github().poll_device_flow(device_code).await? {
        DeviceTokenOutcome::Pending => Ok(Json(PollResponse::status("pending"))),
        DeviceTokenOutcome::SlowDown => Ok(Json(PollResponse::status("slow_down"))),
        DeviceTokenOutcome::Expired => Ok(Json(PollResponse::status("expired"))),
        DeviceTokenOutcome::Denied => Ok(Json(PollResponse::status("denied"))),
        DeviceTokenOutcome::Approved {
            access_token,
            scope,
        } => {
            // Best-effort identity resolution so the audit event is attributable.
            // The authorization already succeeded, so a lookup failure must not
            // deny the token — we still record the event with actor "unknown".
            let (actor, github_id) = match state.github().get_user(&access_token).await {
                Ok(user) => (user.login, Some(user.id)),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "could not resolve identity for device authorization audit"
                    );
                    ("unknown".to_string(), None)
                }
            };

            let mut metadata = json!({ "scopes": scope });
            if let Some(id) = github_id {
                metadata["github_id"] = json!(id);
            }

            // Audit is fail-closed: if the tamper-evident log cannot record the
            // authorization, the request fails rather than silently succeeding.
            state
                .audit()
                .append_audit_event(
                    NewAuditEntry::new("auth.device_authorized", actor).with_metadata(metadata),
                )
                .await?;

            Ok(Json(PollResponse::approved(access_token)))
        }
    }
}

/// `GET /api/v1/auth/whoami` — resolve identity from a Bearer access token.
pub async fn whoami(
    State(state): State<AppState>,
    BearerToken(access_token): BearerToken,
) -> Result<Json<WhoamiResponse>, ApiError> {
    let user = state.github().get_user(&access_token).await?;

    let actor = user.login.clone();
    let github_id = user.id;
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new("auth.identity_lookup", actor)
                .with_metadata(json!({ "github_id": github_id })),
        )
        .await?;

    Ok(Json(WhoamiResponse::from(user)))
}

/// Resolve a GitHub Bearer token into an authorization [`Identity`].
///
/// Fetches org/team membership only when the access policy references them,
/// avoiding extra GitHub calls (and OAuth scopes) for user-only allowlists.
/// Membership-lookup failures fail closed (treated as no memberships), which is
/// safe because authorization is deny-by-default. Shared by certificate
/// issuance and the admin API so both resolve identity identically.
pub async fn resolve_identity(state: &AppState, token: &str) -> Result<Identity, ApiError> {
    let github = state.github();
    let user = github.get_user(token).await?;

    let access = &state.config().access;
    let orgs = if access.allowed_orgs.is_empty() {
        Vec::new()
    } else {
        fetch_or_empty(github.get_user_orgs(token).await, "orgs")
    };
    let teams = if access.allowed_teams.is_empty() {
        Vec::new()
    } else {
        fetch_or_empty(github.get_user_teams(token).await, "teams")
    };

    Ok(Identity {
        login: user.login,
        github_id: user.id,
        orgs,
        teams,
    })
}

/// Use a successful org/team lookup, or treat a failure as "no memberships".
fn fetch_or_empty(
    result: Result<Vec<String>, crate::github::GitHubError>,
    what: &str,
) -> Vec<String> {
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

/// Extractor for an `Authorization: Bearer <token>` header.
///
/// Rejects missing or malformed headers with `401 Unauthorized`. The token is
/// never logged.
#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or_else(|| ApiError::Unauthorized("missing authorization header".to_string()))?;

        let value = header
            .to_str()
            .map_err(|_| ApiError::Unauthorized("malformed authorization header".to_string()))?;

        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                ApiError::Unauthorized("expected 'Bearer <token>' authorization".to_string())
            })?;

        Ok(BearerToken(token.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    async fn extract_bearer(header: Option<&str>) -> Result<BearerToken, ApiError> {
        let mut builder = Request::builder();
        if let Some(h) = header {
            builder = builder.header(AUTHORIZATION, h);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        BearerToken::from_request_parts(&mut parts, &()).await
    }

    #[tokio::test]
    async fn bearer_token_extracts_value() {
        let token = extract_bearer(Some("Bearer gho_secret"))
            .await
            .expect("token");
        assert_eq!(token.0, "gho_secret");
    }

    #[tokio::test]
    async fn bearer_token_accepts_lowercase_scheme() {
        let token = extract_bearer(Some("bearer gho_secret"))
            .await
            .expect("token");
        assert_eq!(token.0, "gho_secret");
    }

    #[tokio::test]
    async fn bearer_token_missing_header_is_unauthorized() {
        let err = extract_bearer(None).await.expect_err("missing");
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn bearer_token_wrong_scheme_is_unauthorized() {
        let err = extract_bearer(Some("Basic abc123"))
            .await
            .expect_err("scheme");
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn bearer_token_empty_value_is_unauthorized() {
        let err = extract_bearer(Some("Bearer    ")).await.expect_err("empty");
        assert!(matches!(err, ApiError::Unauthorized(_)));
    }
}
