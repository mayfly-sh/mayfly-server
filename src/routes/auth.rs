//! GitHub Device Flow authentication endpoints.
//!
//! - `POST /api/v1/auth/device/start` — begin the flow.
//! - `POST /api/v1/auth/device/poll`  — exchange a device code for a token.
//! - `GET  /api/v1/auth/whoami`       — resolve identity from a Bearer token.
//!
//! Handlers depend only on [`AppState`]'s injected [`crate::github::GitHubClient`]
//! and never touch HTTP/GitHub directly. Access tokens and device codes appear
//! only in request/response bodies and are never logged.

use axum::extract::{FromRequestParts, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use crate::audit::{NewAuditEntry, RequestAuditContext};
use crate::auth::{AuthorizationNeeds, DeviceAuthorization, DeviceTokenOutcome};
use crate::authz::Identity;
use crate::config::AccessConfig;
use crate::errors::ApiError;
use crate::github::models::{PollIdentity, PollResponse, WhoamiResponse};
use crate::request_id::RequestId;
use crate::state::AppState;

/// Optional `?provider=<id>` selector for the device flow. Absent or empty
/// selects the configured default provider.
#[derive(Debug, Deserialize, Default)]
pub struct ProviderQuery {
    /// Provider id to authenticate against (e.g. `github`, `keycloak`).
    #[serde(default)]
    pub provider: Option<String>,
}

/// Request body for `POST /api/v1/auth/device/poll`. The optional `provider`
/// must match the one used at `device/start`.
#[derive(Debug, Deserialize)]
pub struct DevicePollBody {
    /// The `device_code` issued by `device/start`.
    pub device_code: String,
    /// Provider id (defaults to the configured default).
    #[serde(default)]
    pub provider: Option<String>,
}

/// Maximum accepted length for a client-supplied `device_code`.
const MAX_DEVICE_CODE_LEN: usize = 256;

/// `POST /api/v1/auth/device/start` — begin a device flow for the selected
/// provider (default GitHub).
pub async fn device_start(
    State(state): State<AppState>,
    Query(query): Query<ProviderQuery>,
) -> Result<Json<DeviceAuthorization>, ApiError> {
    let provider = state.providers().resolve(query.provider.as_deref())?;
    let authorization = provider.start_device_authorization().await?;
    Ok(Json(authorization))
}

/// `POST /api/v1/auth/device/poll` — poll for the device-flow result.
///
/// The `device_code` is read from the JSON body only. Pending/slow_down/
/// expired/denied outcomes are not audited; only a successful authorization is.
pub async fn device_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Json(request): Json<DevicePollBody>,
) -> Result<Json<PollResponse>, ApiError> {
    let provider = state.providers().resolve(request.provider.as_deref())?;
    let device_code = request.device_code.trim();
    if device_code.is_empty() || device_code.len() > MAX_DEVICE_CODE_LEN {
        return Err(ApiError::BadRequest("device_code is required".to_string()));
    }

    match provider.poll_device_authorization(device_code).await? {
        DeviceTokenOutcome::Pending => Ok(Json(PollResponse::status("pending"))),
        DeviceTokenOutcome::SlowDown => Ok(Json(PollResponse::status("slow_down"))),
        DeviceTokenOutcome::Expired => Ok(Json(PollResponse::status("expired"))),
        DeviceTokenOutcome::Denied => Ok(Json(PollResponse::status("denied"))),
        DeviceTokenOutcome::Approved {
            access_token,
            scope,
        } => {
            let provider_id = provider.metadata().id;

            // Best-effort identity resolution so the audit event is attributable
            // and the CLI can persist a provider-agnostic identity. The
            // authorization already succeeded, so a lookup failure must not deny
            // the token — we still record the event with actor "unknown".
            let identity = match provider.fetch_identity(&access_token).await {
                Ok(identity) => Some(identity),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "could not resolve identity for device authorization audit"
                    );
                    None
                }
            };
            let actor = identity
                .as_ref()
                .map(|i| i.username.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let subject = identity.as_ref().map(|i| i.subject.clone());

            // Enterprise client context (privacy-preserving; never tokens/secrets).
            let client = RequestAuditContext::from_headers(
                &headers,
                Some(request_id.as_str()),
                state.clock().now(),
            )
            .with_provider(provider_id.clone());

            let mut metadata = json!({
                "provider": provider_id.clone(),
                "scopes": scope,
                "client": client.to_value(),
            });
            if let Some(subject) = subject {
                metadata["subject"] = json!(subject);
            }

            // Audit is fail-closed: if the tamper-evident log cannot record the
            // authorization, the request fails rather than silently succeeding.
            state
                .audit()
                .append_audit_event(
                    NewAuditEntry::new("auth.device_authorized", actor).with_metadata(metadata),
                )
                .await?;

            let poll_identity = identity.map(|i| PollIdentity {
                provider: provider_id,
                subject: i.subject,
                username: i.username,
                email: i.email,
                name: i.display_name,
            });
            Ok(Json(PollResponse::approved_with(
                access_token,
                poll_identity,
            )))
        }
    }
}

/// `GET /api/v1/auth/whoami` — resolve identity from a Bearer access token.
///
/// Provider-aware: `?provider=<id>` selects the IdP (default provider when
/// absent), and identity is resolved through the provider abstraction — never a
/// direct GitHub call. The response is provider-neutral (`provider`, `subject`,
/// `username`, `name`, `email`) while retaining the legacy `github_login`/
/// `github_id` fields for backward compatibility (populated from `username`/
/// numeric `subject`; `github_id` is `0` for non-GitHub providers).
pub async fn whoami(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<ProviderQuery>,
    BearerToken(access_token): BearerToken,
) -> Result<Json<WhoamiResponse>, ApiError> {
    let provider = state.providers().resolve(query.provider.as_deref())?;
    let provider_id = provider.metadata().id;
    let identity = provider.fetch_identity(&access_token).await?;

    let client =
        RequestAuditContext::from_headers(&headers, Some(request_id.as_str()), state.clock().now())
            .with_provider(provider_id.clone());
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new("auth.identity_lookup", identity.username.clone()).with_metadata(
                json!({
                    "provider": provider_id,
                    "subject": identity.subject,
                    "client": client.to_value(),
                }),
            ),
        )
        .await?;

    Ok(Json(WhoamiResponse::from_identity(&identity)))
}

/// Which authorization facts the configured allowlists actually reference.
///
/// Providers use this to skip work the policy does not need (e.g. GitHub avoids
/// org/team API calls for user-only allowlists).
pub fn needs_from_access(access: &AccessConfig) -> AuthorizationNeeds {
    AuthorizationNeeds {
        organizations: !access.allowed_orgs.is_empty(),
        teams: !access.allowed_teams.is_empty(),
        groups: !access.allowed_groups.is_empty(),
        roles: !access.allowed_roles.is_empty(),
        attributes: !access.allowed_attributes.is_empty(),
    }
}

/// Resolve a Bearer token into a provider-neutral authorization [`Identity`].
///
/// Provider-agnostic: it resolves the selected provider (default when
/// `provider_selector` is absent), maps its [`crate::auth::AuthenticatedIdentity`]
/// into the authorization identity, and asks the provider to resolve only the
/// authorization facts the policy needs (orgs/teams/groups/roles/attributes).
/// Membership-lookup failures fail closed inside each provider (treated as no
/// memberships), which is safe because authorization is deny-by-default. Shared
/// by certificate issuance, server listing, and the admin API so all resolve
/// identity identically across providers.
pub async fn resolve_identity(
    state: &AppState,
    provider_selector: Option<&str>,
    token: &str,
) -> Result<Identity, ApiError> {
    let provider = state.providers().resolve(provider_selector)?;
    let authd = provider.fetch_identity(token).await?;
    let needs = needs_from_access(&state.config().access);
    let context = provider
        .resolve_authorization(token, &authd, &needs)
        .await?;

    Ok(Identity {
        provider: authd.provider,
        subject: authd.subject,
        username: authd.username,
        email: authd.email,
        display_name: authd.display_name,
        realm: context.realm,
        organizations: context.organizations,
        teams: context.teams,
        groups: context.groups,
        roles: context.roles,
        attributes: context.attributes,
    })
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
