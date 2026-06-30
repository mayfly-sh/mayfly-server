//! Keycloak / generic-OIDC [`AuthenticationProvider`].
//!
//! Implements the OIDC device authorization grant against a Keycloak realm (or
//! any OIDC server exposing the device endpoints). It is structurally different
//! from GitHub yet plugs into the same registry and trait, demonstrating that
//! adding a provider requires no changes to authentication logic.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::ACCEPT;

use crate::auth::provider::{
    AuthProviderError, AuthenticatedIdentity, AuthenticationProvider, DeviceAuthorization,
    DeviceTokenOutcome, ProviderKind, ProviderMetadata,
};

/// Provider id for Keycloak/OIDC.
pub const PROVIDER_ID: &str = "keycloak";

/// OAuth device-flow grant type (RFC 8628).
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Configuration for the Keycloak/OIDC provider. Endpoints are derived from
/// `issuer_url` using Keycloak conventions when not given explicitly.
#[derive(Debug, Clone)]
pub struct KeycloakProviderConfig {
    /// Realm base URL, e.g. `https://kc.example.com/realms/engineering`.
    pub issuer_url: String,
    /// OAuth client id.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<String>,
    /// Space-delimited scopes (default `openid profile email`).
    pub scopes: String,
}

impl KeycloakProviderConfig {
    fn issuer(&self) -> String {
        self.issuer_url.trim_end_matches('/').to_string()
    }
    fn device_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/auth/device", self.issuer())
    }
    fn token_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.issuer())
    }
    fn userinfo_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/userinfo", self.issuer())
    }
}

/// Keycloak/OIDC provider backed by `reqwest` (rustls + ring).
///
/// Does not derive `Debug`: it may hold a client secret.
pub struct KeycloakProvider {
    http: reqwest::Client,
    config: KeycloakProviderConfig,
}

impl KeycloakProvider {
    /// Construct the provider from configuration.
    pub fn new(mut config: KeycloakProviderConfig) -> Self {
        if config.scopes.trim().is_empty() {
            config.scopes = "openid profile email".to_string();
        }
        // Mirror RealGitHubClient: ensure a process-default crypto provider is
        // installed so reqwest's rustls config never panics at construction.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let http = reqwest::Client::builder()
            .user_agent("mayfly-server")
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Self { http, config }
    }

    fn transport(err: reqwest::Error) -> AuthProviderError {
        AuthProviderError::Transport(err.to_string())
    }
}

#[async_trait]
impl AuthenticationProvider for KeycloakProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: PROVIDER_ID.to_string(),
            display_name: "Keycloak".to_string(),
            kind: ProviderKind::OidcDevice,
        }
    }

    async fn start_device_authorization(&self) -> Result<DeviceAuthorization, AuthProviderError> {
        let mut form = vec![
            ("client_id", self.config.client_id.as_str()),
            ("scope", self.config.scopes.as_str()),
        ];
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }

        let resp = self
            .http
            .post(self.config.device_endpoint())
            .header(ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(Self::transport)?;

        if !resp.status().is_success() {
            return Err(AuthProviderError::UnexpectedStatus {
                status: resp.status().as_u16(),
            });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AuthProviderError::Decode(e.to_string()))?;

        Ok(DeviceAuthorization {
            device_code: string_field(&body, "device_code")?,
            user_code: string_field(&body, "user_code")?,
            verification_uri: string_field(&body, "verification_uri")?,
            expires_in: body.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(0),
            interval: body.get("interval").and_then(|v| v.as_u64()).unwrap_or(5),
        })
    }

    async fn poll_device_authorization(
        &self,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome, AuthProviderError> {
        let mut form = vec![
            ("client_id", self.config.client_id.as_str()),
            ("device_code", device_code),
            ("grant_type", DEVICE_GRANT_TYPE),
        ];
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }

        let resp = self
            .http
            .post(self.config.token_endpoint())
            .header(ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(Self::transport)?;

        let status = resp.status().as_u16();
        // Keycloak returns 400 for the pending states; 200 for success. Any
        // other status is unexpected.
        if status != 200 && status != 400 {
            return Err(AuthProviderError::UnexpectedStatus { status });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AuthProviderError::Decode(e.to_string()))?;

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
            Some("invalid_grant") | Some("unsupported_grant_type") => {
                Err(AuthProviderError::InvalidDeviceCode)
            }
            _ => Err(AuthProviderError::Decode(
                "token response had neither access_token nor a known error".to_string(),
            )),
        }
    }

    async fn fetch_identity(
        &self,
        access_token: &str,
    ) -> Result<AuthenticatedIdentity, AuthProviderError> {
        let resp = self
            .http
            .get(self.config.userinfo_endpoint())
            .header(ACCEPT, "application/json")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(Self::transport)?;

        match resp.status().as_u16() {
            200 => {}
            401 => return Err(AuthProviderError::Unauthorized),
            429 => return Err(AuthProviderError::RateLimited),
            other => return Err(AuthProviderError::UnexpectedStatus { status: other }),
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AuthProviderError::Decode(e.to_string()))?;

        let subject = string_field(&body, "sub")?;
        let username = body
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .unwrap_or(&subject)
            .to_string();

        Ok(AuthenticatedIdentity {
            provider: PROVIDER_ID.to_string(),
            subject,
            username,
            email: body
                .get("email")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            display_name: body
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
    }
}

fn string_field(body: &serde_json::Value, key: &str) -> Result<String, AuthProviderError> {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| AuthProviderError::Decode(format!("missing field '{key}'")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn provider(issuer: &str) -> KeycloakProvider {
        KeycloakProvider::new(KeycloakProviderConfig {
            issuer_url: issuer.to_string(),
            client_id: "mayfly-cli".into(),
            client_secret: None,
            scopes: String::new(),
        })
    }

    #[tokio::test]
    async fn start_device_authorization_parses_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/auth/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "kc-dc",
                "user_code": "WXYZ-1234",
                "verification_uri": "https://kc.example/device",
                "expires_in": 600,
                "interval": 5
            })))
            .mount(&server)
            .await;

        let auth = provider(&server.uri())
            .start_device_authorization()
            .await
            .expect("start");
        assert_eq!(auth.device_code, "kc-dc");
        assert_eq!(auth.user_code, "WXYZ-1234");
        assert_eq!(auth.expires_in, 600);
    }

    #[tokio::test]
    async fn poll_pending_on_400() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({ "error": "authorization_pending" })),
            )
            .mount(&server)
            .await;

        let outcome = provider(&server.uri())
            .poll_device_authorization("dc")
            .await
            .expect("poll");
        assert_eq!(outcome, DeviceTokenOutcome::Pending);
    }

    #[tokio::test]
    async fn poll_approved_returns_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "kc-token",
                "token_type": "Bearer",
                "scope": "openid profile"
            })))
            .mount(&server)
            .await;

        let outcome = provider(&server.uri())
            .poll_device_authorization("dc")
            .await
            .expect("poll");
        assert_eq!(
            outcome,
            DeviceTokenOutcome::Approved {
                access_token: "kc-token".into(),
                scope: "openid profile".into()
            }
        );
    }

    #[tokio::test]
    async fn fetch_identity_maps_userinfo() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sub": "abc-123",
                "preferred_username": "vasu",
                "email": "vasu@example.com",
                "name": "Vasu Garg"
            })))
            .mount(&server)
            .await;

        let identity = provider(&server.uri())
            .fetch_identity("kc-token")
            .await
            .expect("identity");
        assert_eq!(identity.provider, "keycloak");
        assert_eq!(identity.subject, "abc-123");
        assert_eq!(identity.username, "vasu");
        assert_eq!(identity.email.as_deref(), Some("vasu@example.com"));
    }

    #[tokio::test]
    async fn fetch_identity_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/userinfo"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let err = provider(&server.uri())
            .fetch_identity("bad")
            .await
            .expect_err("401");
        assert!(matches!(err, AuthProviderError::Unauthorized));
    }
}
