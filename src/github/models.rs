//! Typed models for GitHub Device Flow and identity, plus Mayfly's API DTOs.
//!
//! GitHub wire models are `Deserialize`-only; Mayfly API responses are
//! `Serialize`. Access tokens are carried only inside [`DeviceTokenOutcome`]
//! and [`PollResponse`] and are never placed in `Debug`, logs, or audit data.

use serde::{Deserialize, Serialize};

/// GitHub's response to `POST /login/device/code`.
///
/// Returned to the client verbatim by `POST /api/v1/auth/device/start`; the
/// fields are explicit (not a passthrough) so unexpected additions never leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    /// Long, secret code the server uses when polling. Treated as sensitive:
    /// only ever transported in request/response bodies, never logged.
    pub device_code: String,
    /// Short code the user types at `verification_uri`.
    pub user_code: String,
    /// Where the user approves (e.g. `https://github.com/login/device`).
    pub verification_uri: String,
    /// Seconds until `device_code`/`user_code` expire.
    pub expires_in: u64,
    /// Minimum seconds the client must wait between polls.
    pub interval: u64,
}

/// GitHub's success body from `POST /login/oauth/access_token`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAccessToken {
    /// The OAuth access token. Sensitive — never logged.
    pub access_token: String,
    /// Token type, e.g. `"bearer"`.
    #[allow(dead_code)]
    pub token_type: String,
    /// Granted scopes, space-delimited.
    #[serde(default)]
    pub scope: String,
}

/// GitHub's error body from the token endpoint (returned with HTTP 200).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceErrorBody {
    /// Machine-readable error code, e.g. `authorization_pending`.
    pub error: String,
}

/// Identity returned by `GET /user`.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubUser {
    /// GitHub login (username).
    pub login: String,
    /// Numeric GitHub user id.
    pub id: u64,
    /// Display name, if set.
    #[serde(default)]
    pub name: Option<String>,
    /// Primary email, if visible to the token's scopes.
    #[serde(default)]
    pub email: Option<String>,
}

/// An entry from `GET /user/orgs`.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubOrg {
    /// Org login (the identifier used in `allowed_orgs`).
    pub login: String,
}

/// An entry from `GET /user/teams`.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubTeam {
    /// Team slug (unique within its org).
    pub slug: String,
    /// The org that owns the team.
    pub organization: GitHubOrgRef,
}

/// The `organization` object nested inside a team.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubOrgRef {
    /// Org login.
    pub login: String,
}

/// Outcome of a device-token poll, normalized away from GitHub's wire strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceTokenOutcome {
    /// User has not yet approved; keep polling at the current interval.
    Pending,
    /// Polling too fast; keep polling with a larger interval.
    SlowDown,
    /// The device code expired; the flow must restart.
    Expired,
    /// The user denied authorization.
    Denied,
    /// Authorization succeeded.
    Approved {
        /// The access token to hand back to the client.
        access_token: String,
        /// Space-delimited granted scopes (for auditing).
        scope: String,
    },
}

/// Request body for `POST /api/v1/auth/device/poll` (body-only; never a query).
#[derive(Debug, Clone, Deserialize)]
pub struct DevicePollRequest {
    /// The `device_code` issued by `device/start`.
    pub device_code: String,
}

/// Provider-agnostic identity echoed to the client on an approved poll, so the
/// CLI can persist the authenticated identity for any provider without a
/// GitHub-specific `whoami` call. Contains no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PollIdentity {
    /// Provider id that authenticated the identity.
    pub provider: String,
    /// Stable, provider-unique subject.
    pub subject: String,
    /// Human username/login.
    pub username: String,
    /// Email, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Display name, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Response for `POST /api/v1/auth/device/poll`.
#[derive(Debug, Clone, Serialize)]
pub struct PollResponse {
    /// One of `pending`, `slow_down`, `expired`, `denied`, `approved`.
    pub status: &'static str,
    /// Present only when `status == "approved"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Present (best-effort) when `status == "approved"` and identity resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<PollIdentity>,
}

impl PollResponse {
    /// A status-only response (no token).
    pub fn status(status: &'static str) -> Self {
        Self {
            status,
            access_token: None,
            identity: None,
        }
    }

    /// An approved response carrying the access token (no identity).
    pub fn approved(access_token: String) -> Self {
        Self {
            status: "approved",
            access_token: Some(access_token),
            identity: None,
        }
    }

    /// An approved response carrying the access token and resolved identity.
    pub fn approved_with(access_token: String, identity: Option<PollIdentity>) -> Self {
        Self {
            status: "approved",
            access_token: Some(access_token),
            identity,
        }
    }
}

/// Response for `GET /api/v1/auth/whoami`.
///
/// Provider-neutral: `provider`/`subject`/`username`/`name`/`email` describe the
/// authenticated identity for any provider. The legacy `github_login`/`github_id`
/// fields are retained for backward compatibility — `github_login` mirrors
/// `username`, and `github_id` is the numeric `subject` for GitHub (`0` for
/// providers whose subject is not numeric, e.g. an OIDC `sub`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhoamiResponse {
    /// Provider id that authenticated the identity.
    pub provider: String,
    /// Stable, provider-unique subject.
    pub subject: String,
    /// Human username/login.
    pub username: String,
    /// Display name, if any.
    pub name: Option<String>,
    /// Email, if any.
    pub email: Option<String>,
    /// Legacy GitHub login alias of `username` (backward compatibility).
    pub github_login: String,
    /// Legacy GitHub numeric id; `0` for non-GitHub providers.
    pub github_id: u64,
}

impl WhoamiResponse {
    /// Build a provider-neutral whoami response from an authenticated identity.
    pub fn from_identity(identity: &crate::auth::AuthenticatedIdentity) -> Self {
        Self {
            provider: identity.provider.clone(),
            subject: identity.subject.clone(),
            username: identity.username.clone(),
            name: identity.display_name.clone(),
            email: identity.email.clone(),
            github_login: identity.username.clone(),
            github_id: identity.subject.parse().unwrap_or(0),
        }
    }
}
