//! The provider-agnostic authentication abstraction.
//!
//! Every identity provider (GitHub, Keycloak, and future GitLab/Okta/Azure/
//! Google/generic OIDC) implements [`AuthenticationProvider`]. Handlers resolve
//! a provider from the [`crate::auth::ProviderRegistry`] by id and call the
//! trait — they never branch on the concrete provider, so adding a provider is
//! "implement the trait and register it" with no edits to authentication logic.

use async_trait::async_trait;
use thiserror::Error;

use crate::errors::ApiError;
use crate::github::GitHubError;

// The device-flow wire types are shared across providers (RFC 8628 shapes).
pub use crate::github::{DeviceAuthorization, DeviceTokenOutcome};

/// How a provider authenticates, for diagnostics/audit only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Plain OAuth 2.0 device authorization grant (RFC 8628).
    OAuth2Device,
    /// OpenID Connect device authorization grant.
    OidcDevice,
}

impl ProviderKind {
    /// Stable string form used in audit metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderKind::OAuth2Device => "oauth2-device",
            ProviderKind::OidcDevice => "oidc-device",
        }
    }
}

/// Non-secret descriptive metadata about a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadata {
    /// Stable id used to select the provider (e.g. `"github"`, `"keycloak"`).
    pub id: String,
    /// Human-facing name (e.g. `"GitHub"`).
    pub display_name: String,
    /// Authentication protocol.
    pub kind: ProviderKind,
}

/// A normalized, provider-agnostic authenticated identity.
///
/// Certificate principals are derived from the authenticated identity only, so
/// this type is the single source of "who is the caller" regardless of provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedIdentity {
    /// Provider id that authenticated this identity.
    pub provider: String,
    /// Stable, provider-unique subject (GitHub numeric id, OIDC `sub`, ...).
    pub subject: String,
    /// Human username/login (GitHub login, OIDC `preferred_username`).
    pub username: String,
    /// Email, when the provider/scopes expose it.
    pub email: Option<String>,
    /// Display name, when available.
    pub display_name: Option<String>,
}

/// An in-progress device-flow authentication, bound to a provider.
///
/// The server is stateless across device-flow polls (it proxies to the
/// provider), so this simply pairs the selected provider id with the
/// authorization the provider returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSession {
    /// Provider id that issued the authorization.
    pub provider: String,
    /// The device authorization returned to the client.
    pub authorization: DeviceAuthorization,
}

/// Failures common to all authentication providers.
///
/// Like [`GitHubError`], these never carry tokens, secrets, or device codes —
/// only coarse, non-sensitive context safe to log server-side.
#[derive(Debug, Error)]
pub enum AuthProviderError {
    /// Network/transport failure (DNS, TLS, timeout, connection reset).
    #[error("auth provider transport error: {0}")]
    Transport(String),

    /// The provider returned a status we do not handle for this call.
    #[error("auth provider returned unexpected status {status}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: u16,
    },

    /// The provider's response body could not be parsed into the expected shape.
    #[error("failed to decode auth provider response: {0}")]
    Decode(String),

    /// The supplied access token was rejected (401).
    #[error("auth provider rejected the access token")]
    Unauthorized,

    /// The provider rate-limited the request.
    #[error("auth provider rate limit exceeded")]
    RateLimited,

    /// The device code/grant was rejected by the provider.
    #[error("auth provider rejected the device code")]
    InvalidDeviceCode,

    /// No provider is registered under the requested id.
    #[error("unknown authentication provider")]
    UnknownProvider,
}

impl From<GitHubError> for AuthProviderError {
    fn from(err: GitHubError) -> Self {
        match err {
            GitHubError::Transport(m) => AuthProviderError::Transport(m),
            GitHubError::UnexpectedStatus { status } => {
                AuthProviderError::UnexpectedStatus { status }
            }
            GitHubError::Decode(m) => AuthProviderError::Decode(m),
            GitHubError::Unauthorized => AuthProviderError::Unauthorized,
            GitHubError::RateLimited => AuthProviderError::RateLimited,
            GitHubError::InvalidDeviceCode => AuthProviderError::InvalidDeviceCode,
        }
    }
}

impl From<AuthProviderError> for ApiError {
    fn from(err: AuthProviderError) -> Self {
        match err {
            AuthProviderError::Unauthorized => {
                ApiError::Unauthorized("the access token is invalid or expired".to_string())
            }
            AuthProviderError::RateLimited => {
                ApiError::TooManyRequests("upstream rate limit exceeded; retry later".to_string())
            }
            AuthProviderError::InvalidDeviceCode => {
                ApiError::BadRequest("the device_code is invalid".to_string())
            }
            AuthProviderError::UnknownProvider => {
                ApiError::BadRequest("unknown authentication provider".to_string())
            }
            // Transport, unexpected status, and decode failures are upstream
            // problems the client cannot fix; surface a generic 500 and log the
            // detail server-side.
            other => ApiError::Internal(anyhow::Error::new(other)),
        }
    }
}

/// The single interface every identity provider implements.
#[async_trait]
pub trait AuthenticationProvider: Send + Sync {
    /// Non-secret descriptive metadata.
    fn metadata(&self) -> ProviderMetadata;

    /// Begin a device authorization flow (RFC 8628).
    async fn start_device_authorization(&self) -> Result<DeviceAuthorization, AuthProviderError>;

    /// Poll for the device-flow result.
    async fn poll_device_authorization(
        &self,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome, AuthProviderError>;

    /// Resolve the authenticated identity behind an access token.
    async fn fetch_identity(
        &self,
        access_token: &str,
    ) -> Result<AuthenticatedIdentity, AuthProviderError>;
}
