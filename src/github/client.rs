//! The [`GitHubClient`] trait and its production implementation.
//!
//! Handlers depend only on `Arc<dyn GitHubClient>`, so GitHub is fully mockable
//! and no handler ever performs HTTP directly.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{ACCEPT, USER_AGENT};

use crate::config::GithubConfig;
use crate::github::errors::GitHubError;
use crate::github::models::{
    DeviceAuthorization, DeviceTokenOutcome, GitHubOrg, GitHubTeam, GitHubUser,
};

/// OAuth device-flow grant type (RFC 8628).
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Abstraction over the subset of GitHub's API that Mayfly uses.
#[async_trait]
pub trait GitHubClient: Send + Sync {
    /// Begin the device flow (`POST /login/device/code`).
    async fn start_device_flow(&self) -> Result<DeviceAuthorization, GitHubError>;

    /// Poll for the device-flow result (`POST /login/oauth/access_token`).
    async fn poll_device_flow(&self, device_code: &str) -> Result<DeviceTokenOutcome, GitHubError>;

    /// Resolve the identity behind an access token (`GET /user`).
    async fn get_user(&self, access_token: &str) -> Result<GitHubUser, GitHubError>;

    /// List the org logins the token's user belongs to (`GET /user/orgs`).
    async fn get_user_orgs(&self, access_token: &str) -> Result<Vec<String>, GitHubError>;

    /// List the teams the token's user belongs to (`GET /user/teams`),
    /// each formatted `org-login/team-slug`.
    async fn get_user_teams(&self, access_token: &str) -> Result<Vec<String>, GitHubError>;
}

/// Production [`GitHubClient`] backed by `reqwest` (rustls + ring).
///
/// Does not derive `Debug`: it holds the client secret, which must never be
/// rendered. Base URLs are configurable so tests (wiremock) and GitHub
/// Enterprise deployments can override the default GitHub endpoints.
pub struct RealGitHubClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    scope: String,
    device_base_url: String,
    api_base_url: String,
}

impl RealGitHubClient {
    /// Construct a client with explicit endpoints (used by tests).
    pub fn new(
        client_id: String,
        client_secret: String,
        scope: String,
        device_base_url: String,
        api_base_url: String,
    ) -> Self {
        // reqwest 0.12 builds its rustls `ClientConfig` from the process-default
        // crypto provider. Install ring (idempotent) so construction never
        // panics regardless of call site; our own TLS listener passes ring
        // explicitly, so only one provider is ever in play.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let http = reqwest::Client::builder()
            .user_agent("mayfly-server")
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Self {
            http,
            client_id,
            client_secret,
            scope,
            device_base_url: device_base_url.trim_end_matches('/').to_string(),
            api_base_url: api_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Construct a client from validated configuration.
    pub fn from_config(config: &GithubConfig) -> Self {
        Self::new(
            config.client_id.clone(),
            config.client_secret_value(),
            config.scopes.clone(),
            config.device_base_url.clone(),
            config.api_base_url.clone(),
        )
    }
}

fn transport(err: reqwest::Error) -> GitHubError {
    // `reqwest::Error` Display may include the URL but never headers, so no
    // bearer token or secret can leak here.
    GitHubError::Transport(err.to_string())
}

/// Map a non-success status from a token-authenticated GET to a [`GitHubError`].
///
/// 403 with `x-ratelimit-remaining: 0` is GitHub's secondary rate-limit signal;
/// any other 403 is surfaced as an unexpected status.
fn auth_status_error(resp: &reqwest::Response) -> GitHubError {
    match resp.status().as_u16() {
        401 => GitHubError::Unauthorized,
        429 => GitHubError::RateLimited,
        403 => {
            let exhausted = resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim() == "0")
                .unwrap_or(false);
            if exhausted {
                GitHubError::RateLimited
            } else {
                GitHubError::UnexpectedStatus { status: 403 }
            }
        }
        other => GitHubError::UnexpectedStatus { status: other },
    }
}

#[async_trait]
impl GitHubClient for RealGitHubClient {
    async fn start_device_flow(&self) -> Result<DeviceAuthorization, GitHubError> {
        let resp = self
            .http
            .post(format!("{}/login/device/code", self.device_base_url))
            .header(ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", self.scope.as_str()),
            ])
            .send()
            .await
            .map_err(transport)?;

        if !resp.status().is_success() {
            return Err(GitHubError::UnexpectedStatus {
                status: resp.status().as_u16(),
            });
        }

        resp.json::<DeviceAuthorization>()
            .await
            .map_err(|err| GitHubError::Decode(err.to_string()))
    }

    async fn poll_device_flow(&self, device_code: &str) -> Result<DeviceTokenOutcome, GitHubError> {
        let resp = self
            .http
            .post(format!("{}/login/oauth/access_token", self.device_base_url))
            .header(ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("device_code", device_code),
                ("grant_type", DEVICE_GRANT_TYPE),
            ])
            .send()
            .await
            .map_err(transport)?;

        // GitHub returns HTTP 200 for both success and the pending/slow_down/
        // expired/denied states, distinguished by the body.
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|err| GitHubError::Decode(err.to_string()))?;

        if let Some(token) = body.get("access_token").and_then(|v| v.as_str()) {
            let scope = body
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            return Ok(DeviceTokenOutcome::Approved {
                access_token: token.to_string(),
                scope,
            });
        }

        match body.get("error").and_then(|v| v.as_str()) {
            Some("authorization_pending") => Ok(DeviceTokenOutcome::Pending),
            Some("slow_down") => Ok(DeviceTokenOutcome::SlowDown),
            Some("expired_token") => Ok(DeviceTokenOutcome::Expired),
            Some("access_denied") => Ok(DeviceTokenOutcome::Denied),
            Some("incorrect_device_code")
            | Some("invalid_grant")
            | Some("unsupported_grant_type") => Err(GitHubError::InvalidDeviceCode),
            _ => Err(GitHubError::Decode(
                "token response had neither access_token nor a known error".to_string(),
            )),
        }
    }

    async fn get_user(&self, access_token: &str) -> Result<GitHubUser, GitHubError> {
        let resp = self
            .http
            .get(format!("{}/user", self.api_base_url))
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "mayfly-server")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;

        if resp.status().as_u16() == 200 {
            resp.json::<GitHubUser>()
                .await
                .map_err(|err| GitHubError::Decode(err.to_string()))
        } else {
            Err(auth_status_error(&resp))
        }
    }

    async fn get_user_orgs(&self, access_token: &str) -> Result<Vec<String>, GitHubError> {
        let resp = self
            .http
            .get(format!("{}/user/orgs", self.api_base_url))
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "mayfly-server")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;

        if resp.status().as_u16() != 200 {
            return Err(auth_status_error(&resp));
        }

        let orgs = resp
            .json::<Vec<GitHubOrg>>()
            .await
            .map_err(|err| GitHubError::Decode(err.to_string()))?;
        Ok(orgs.into_iter().map(|org| org.login).collect())
    }

    async fn get_user_teams(&self, access_token: &str) -> Result<Vec<String>, GitHubError> {
        let resp = self
            .http
            .get(format!("{}/user/teams", self.api_base_url))
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "mayfly-server")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(transport)?;

        if resp.status().as_u16() != 200 {
            return Err(auth_status_error(&resp));
        }

        let teams = resp
            .json::<Vec<GitHubTeam>>()
            .await
            .map_err(|err| GitHubError::Decode(err.to_string()))?;
        Ok(teams
            .into_iter()
            .map(|team| format!("{}/{}", team.organization.login, team.slug))
            .collect())
    }
}

/// A [`GitHubClient`] that fails every call.
///
/// Used as the default in [`crate::state::AppState`] so the auth routes return
/// a clean 500 if the server is somehow constructed without a real client. In
/// production, `main` always installs [`RealGitHubClient`].
pub struct UnconfiguredGitHubClient;

#[async_trait]
impl GitHubClient for UnconfiguredGitHubClient {
    async fn start_device_flow(&self) -> Result<DeviceAuthorization, GitHubError> {
        Err(GitHubError::Transport(
            "github client is not configured".into(),
        ))
    }
    async fn poll_device_flow(&self, _: &str) -> Result<DeviceTokenOutcome, GitHubError> {
        Err(GitHubError::Transport(
            "github client is not configured".into(),
        ))
    }
    async fn get_user(&self, _: &str) -> Result<GitHubUser, GitHubError> {
        Err(GitHubError::Transport(
            "github client is not configured".into(),
        ))
    }
    async fn get_user_orgs(&self, _: &str) -> Result<Vec<String>, GitHubError> {
        Err(GitHubError::Transport(
            "github client is not configured".into(),
        ))
    }
    async fn get_user_teams(&self, _: &str) -> Result<Vec<String>, GitHubError> {
        Err(GitHubError::Transport(
            "github client is not configured".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(base: &str) -> RealGitHubClient {
        RealGitHubClient::new(
            "client-id".into(),
            "client-secret".into(),
            "read:user user:email".into(),
            base.to_string(),
            base.to_string(),
        )
    }

    async fn mount_token_error(server: &MockServer, error: &str) {
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "error": error })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn start_device_flow_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .and(header("accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "dc-123",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5
            })))
            .mount(&server)
            .await;

        let auth = client(&server.uri())
            .start_device_flow()
            .await
            .expect("start");
        assert_eq!(auth.device_code, "dc-123");
        assert_eq!(auth.user_code, "ABCD-EFGH");
        assert_eq!(auth.expires_in, 900);
        assert_eq!(auth.interval, 5);
    }

    #[tokio::test]
    async fn start_device_flow_github_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .start_device_flow()
            .await
            .expect_err("fail");
        assert!(matches!(err, GitHubError::UnexpectedStatus { status: 500 }));
    }

    #[tokio::test]
    async fn poll_pending() {
        let server = MockServer::start().await;
        mount_token_error(&server, "authorization_pending").await;
        let outcome = client(&server.uri())
            .poll_device_flow("dc")
            .await
            .expect("poll");
        assert_eq!(outcome, DeviceTokenOutcome::Pending);
    }

    #[tokio::test]
    async fn poll_slow_down() {
        let server = MockServer::start().await;
        mount_token_error(&server, "slow_down").await;
        let outcome = client(&server.uri())
            .poll_device_flow("dc")
            .await
            .expect("poll");
        assert_eq!(outcome, DeviceTokenOutcome::SlowDown);
    }

    #[tokio::test]
    async fn poll_expired() {
        let server = MockServer::start().await;
        mount_token_error(&server, "expired_token").await;
        let outcome = client(&server.uri())
            .poll_device_flow("dc")
            .await
            .expect("poll");
        assert_eq!(outcome, DeviceTokenOutcome::Expired);
    }

    #[tokio::test]
    async fn poll_denied() {
        let server = MockServer::start().await;
        mount_token_error(&server, "access_denied").await;
        let outcome = client(&server.uri())
            .poll_device_flow("dc")
            .await
            .expect("poll");
        assert_eq!(outcome, DeviceTokenOutcome::Denied);
    }

    #[tokio::test]
    async fn poll_approved() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "gho_secret",
                "token_type": "bearer",
                "scope": "read:user"
            })))
            .mount(&server)
            .await;

        let outcome = client(&server.uri())
            .poll_device_flow("dc")
            .await
            .expect("poll");
        assert_eq!(
            outcome,
            DeviceTokenOutcome::Approved {
                access_token: "gho_secret".into(),
                scope: "read:user".into()
            }
        );
    }

    #[tokio::test]
    async fn get_user_valid_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("authorization", "Bearer gho_secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "login": "vasugarg",
                "id": 12345,
                "name": "Vasu Garg",
                "email": "vasu@example.com"
            })))
            .mount(&server)
            .await;

        let user = client(&server.uri())
            .get_user("gho_secret")
            .await
            .expect("user");
        assert_eq!(user.login, "vasugarg");
        assert_eq!(user.id, 12345);
        assert_eq!(user.name.as_deref(), Some("Vasu Garg"));
    }

    #[tokio::test]
    async fn get_user_invalid_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .get_user("bad")
            .await
            .expect_err("401");
        assert!(matches!(err, GitHubError::Unauthorized));
    }

    #[tokio::test]
    async fn get_user_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{ not json"))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .get_user("tok")
            .await
            .expect_err("decode");
        assert!(matches!(err, GitHubError::Decode(_)));
    }

    #[tokio::test]
    async fn get_user_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(403).insert_header("x-ratelimit-remaining", "0"))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .get_user("tok")
            .await
            .expect_err("rate");
        assert!(matches!(err, GitHubError::RateLimited));
    }

    #[tokio::test]
    async fn get_user_orgs_returns_logins() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/orgs"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "login": "acme", "id": 1 },
                { "login": "globex", "id": 2 }
            ])))
            .mount(&server)
            .await;

        let orgs = client(&server.uri())
            .get_user_orgs("tok")
            .await
            .expect("orgs");
        assert_eq!(orgs, vec!["acme".to_string(), "globex".to_string()]);
    }

    #[tokio::test]
    async fn get_user_teams_formats_org_slash_slug() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/teams"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "slug": "platform", "organization": { "login": "acme" } },
                { "slug": "sre", "organization": { "login": "globex" } }
            ])))
            .mount(&server)
            .await;

        let teams = client(&server.uri())
            .get_user_teams("tok")
            .await
            .expect("teams");
        assert_eq!(
            teams,
            vec!["acme/platform".to_string(), "globex/sre".to_string()]
        );
    }

    #[tokio::test]
    async fn get_user_orgs_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user/orgs"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .get_user_orgs("bad")
            .await
            .expect_err("401");
        assert!(matches!(err, GitHubError::Unauthorized));
    }
}
