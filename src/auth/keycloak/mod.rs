//! Keycloak / generic-OIDC [`AuthenticationProvider`].
//!
//! A first-class OIDC provider: the device authorization grant (RFC 8628) for
//! login, and **JWT access-token verification** for identity + authorization.
//! Verification performs OIDC discovery, fetches and caches the realm's JWKS
//! (refreshing on key rotation), and validates the token's signature, issuer,
//! audience, and `exp`/`nbf` (with clock-skew leeway), pinning the signing
//! algorithm to the JWK key type so it cannot be downgraded.
//!
//! It plugs into the same [`crate::auth::ProviderRegistry`] and
//! [`AuthenticationProvider`] trait as GitHub: no authentication-logic changes
//! are required to add it, and no handler branches on the provider.

mod claims;
mod config;
mod oidc;
mod verify;

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::ACCEPT;

use crate::auth::provider::{
    AuthProviderError, AuthenticatedIdentity, AuthenticationProvider, AuthorizationContext,
    AuthorizationNeeds, DeviceAuthorization, DeviceTokenOutcome, ProviderKind, ProviderMetadata,
};

pub use config::{KeycloakProviderConfig, DEFAULT_CLOCK_SKEW_SECS};
use oidc::OidcCache;

/// Provider id for Keycloak/OIDC.
pub const PROVIDER_ID: &str = "keycloak";

/// OAuth device-flow grant type (RFC 8628).
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Keycloak/OIDC provider backed by `reqwest` (rustls + ring) and `jsonwebtoken`.
///
/// Does not derive `Debug`: it may hold a client secret.
pub struct KeycloakProvider {
    http: reqwest::Client,
    config: KeycloakProviderConfig,
    oidc: OidcCache,
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

        let oidc = OidcCache::new(http.clone(), config.discovery_url());
        Self { http, config, oidc }
    }

    fn transport(err: reqwest::Error) -> AuthProviderError {
        AuthProviderError::Transport(err.to_string())
    }

    /// Resolve the device-authorization endpoint (discovery, then convention).
    async fn device_endpoint(&self) -> String {
        match self.oidc.discovery().await {
            Ok(d) => d
                .device_authorization_endpoint
                .unwrap_or_else(|| self.config.device_endpoint_convention()),
            Err(_) => self.config.device_endpoint_convention(),
        }
    }

    /// Resolve the token endpoint (discovery, then convention).
    async fn token_endpoint(&self) -> String {
        match self.oidc.discovery().await {
            Ok(d) => d
                .token_endpoint
                .unwrap_or_else(|| self.config.token_endpoint_convention()),
            Err(_) => self.config.token_endpoint_convention(),
        }
    }

    /// Verify an access token, returning its claims and the canonical issuer.
    async fn verified_claims(
        &self,
        access_token: &str,
    ) -> Result<(claims::KeycloakClaims, String), AuthProviderError> {
        let discovery = self.oidc.discovery().await?;
        let header = jsonwebtoken::decode_header(access_token)
            .map_err(|e| AuthProviderError::Decode(e.to_string()))?;
        let kid = header
            .kid
            .ok_or_else(|| AuthProviderError::Decode("access token has no 'kid'".to_string()))?;
        let jwk = self.oidc.jwk_for_kid(&kid).await?;
        let claims = verify::verify_access_token(access_token, &jwk, &discovery, &self.config)?;
        Ok((claims, discovery.issuer))
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
        let endpoint = self.device_endpoint().await;
        let mut form = vec![
            ("client_id", self.config.client_id.as_str()),
            ("scope", self.config.scopes.as_str()),
        ];
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }

        let resp = self
            .http
            .post(endpoint)
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
        let endpoint = self.token_endpoint().await;
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
            .post(endpoint)
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
        let (claims, _issuer) = self.verified_claims(access_token).await?;
        Ok(claims.to_identity())
    }

    async fn resolve_authorization(
        &self,
        access_token: &str,
        _identity: &AuthenticatedIdentity,
        _needs: &AuthorizationNeeds,
    ) -> Result<AuthorizationContext, AuthProviderError> {
        let (claims, issuer) = self.verified_claims(access_token).await?;
        Ok(claims.to_authorization(&issuer))
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
    use base64::Engine;
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A minimal in-test OIDC identity provider: an RSA signing key, a JWKS, a
    /// discovery document, and a token minter.
    struct TestIdp {
        kid: String,
        encoding: EncodingKey,
        jwk: serde_json::Value,
        issuer: String,
    }

    impl TestIdp {
        fn new(issuer: &str, kid: &str) -> Self {
            let mut rng = rand_core::OsRng;
            let key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
            let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).expect("pem");
            let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");

            let pubkey = key.to_public_key();
            let n =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
            let e =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
            let jwk = json!({
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "alg": "RS256",
                "n": n,
                "e": e,
            });
            Self {
                kid: kid.to_string(),
                encoding,
                jwk,
                issuer: issuer.to_string(),
            }
        }

        fn jwks(&self) -> serde_json::Value {
            json!({ "keys": [ self.jwk.clone() ] })
        }

        fn discovery(&self) -> serde_json::Value {
            json!({
                "issuer": self.issuer,
                "token_endpoint": format!("{}/protocol/openid-connect/token", self.issuer),
                "device_authorization_endpoint": format!("{}/protocol/openid-connect/auth/device", self.issuer),
                "jwks_uri": format!("{}/protocol/openid-connect/certs", self.issuer),
            })
        }

        /// Mint a signed RS256 token from a claims object (the test fills `iss`,
        /// `exp`, `iat` unless overridden).
        fn mint(&self, mut claims: serde_json::Value) -> String {
            let obj = claims.as_object_mut().expect("claims object");
            obj.entry("iss").or_insert(json!(self.issuer));
            let now = Utc::now().timestamp();
            obj.entry("iat").or_insert(json!(now));
            obj.entry("exp").or_insert(json!(now + 300));
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(self.kid.clone());
            jsonwebtoken::encode(&header, &claims, &self.encoding).expect("encode token")
        }
    }

    /// Start a mock server and an IdP whose issuer is that server, with the
    /// standard discovery + JWKS endpoints mounted (issuer = mock).
    async fn idp_server() -> (MockServer, TestIdp) {
        let server = MockServer::start().await;
        let idp = TestIdp::new(&server.uri(), "k1");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(idp.discovery()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(idp.jwks()))
            .mount(&server)
            .await;
        (server, idp)
    }

    fn provider(issuer: &str, audience: Option<&str>) -> KeycloakProvider {
        KeycloakProvider::new(KeycloakProviderConfig {
            issuer_url: issuer.to_string(),
            client_id: "mayfly-cli".into(),
            client_secret: None,
            scopes: String::new(),
            audience: audience.map(str::to_string),
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
        })
    }

    #[tokio::test]
    async fn start_device_authorization_uses_discovery_endpoint() {
        let server = MockServer::start().await;
        let idp = TestIdp::new(&server.uri(), "k1");
        // Discovery advertises the device endpoint on the mock.
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(idp.discovery()))
            .mount(&server)
            .await;
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

        let auth = provider(&server.uri(), None)
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

        // No discovery mounted: provider falls back to the convention endpoint.
        let outcome = provider(&server.uri(), None)
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

        let outcome = provider(&server.uri(), None)
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
    async fn fetch_identity_verifies_jwt_and_maps_claims() {
        let (server, idp) = idp_server().await;
        let token = idp.mint(json!({
            "sub": "abc-123",
            "preferred_username": "vasu",
            "email": "vasu@example.com",
            "name": "Vasu Garg",
        }));

        let identity = provider(&server.uri(), None)
            .fetch_identity(&token)
            .await
            .expect("identity");
        assert_eq!(identity.provider, "keycloak");
        assert_eq!(identity.subject, "abc-123");
        assert_eq!(identity.username, "vasu");
        assert_eq!(identity.email.as_deref(), Some("vasu@example.com"));
    }

    #[tokio::test]
    async fn resolve_authorization_extracts_groups_and_roles() {
        let (server, idp) = idp_server().await;
        let token = idp.mint(json!({
            "sub": "abc-123",
            "preferred_username": "vasu",
            "groups": ["/engineering", "ops"],
            "realm_access": { "roles": ["admin"] },
            "resource_access": { "mayfly": { "roles": ["operator"] } },
        }));

        let identity = AuthenticatedIdentity {
            provider: "keycloak".into(),
            subject: "abc-123".into(),
            username: "vasu".into(),
            email: None,
            display_name: None,
        };
        let ctx = provider(&server.uri(), None)
            .resolve_authorization(&token, &identity, &AuthorizationNeeds::all())
            .await
            .expect("authz");
        assert!(ctx.groups.contains(&"engineering".to_string()));
        assert!(ctx.groups.contains(&"ops".to_string()));
        assert!(ctx.roles.contains(&"admin".to_string()));
        assert!(ctx.roles.contains(&"mayfly/operator".to_string()));
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (server, idp) = idp_server().await;
        let now = Utc::now().timestamp();
        let token = idp.mint(json!({
            "sub": "abc",
            "preferred_username": "vasu",
            "iat": now - 1000,
            "exp": now - 600,
        }));

        let err = provider(&server.uri(), None)
            .fetch_identity(&token)
            .await
            .expect_err("expired");
        assert!(matches!(err, AuthProviderError::Unauthorized));
    }

    #[tokio::test]
    async fn token_expired_within_clock_skew_is_accepted() {
        let (server, idp) = idp_server().await;
        let now = Utc::now().timestamp();
        // Expired 30s ago, but within the 60s clock-skew leeway.
        let token = idp.mint(json!({
            "sub": "abc",
            "preferred_username": "vasu",
            "iat": now - 120,
            "exp": now - 30,
        }));
        let identity = provider(&server.uri(), None)
            .fetch_identity(&token)
            .await
            .expect("within leeway");
        assert_eq!(identity.username, "vasu");
    }

    #[tokio::test]
    async fn wrong_issuer_is_rejected() {
        let server = MockServer::start().await;
        // Discovery reports a different issuer than the token will carry.
        let idp = TestIdp::new("https://evil.invalid", "k1");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": "https://trusted.invalid",
                "jwks_uri": format!("{}/protocol/openid-connect/certs", server.uri()),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(idp.jwks()))
            .mount(&server)
            .await;

        let token = idp.mint(json!({ "sub": "abc", "iss": "https://evil.invalid" }));
        let err = provider(&server.uri(), None)
            .fetch_identity(&token)
            .await
            .expect_err("issuer");
        assert!(matches!(err, AuthProviderError::Unauthorized));
    }

    #[tokio::test]
    async fn correct_audience_is_accepted() {
        let (server, idp) = idp_server().await;
        let token = idp.mint(
            json!({ "sub": "abc", "preferred_username": "vasu", "aud": "expected-audience" }),
        );
        let identity = provider(&server.uri(), Some("expected-audience"))
            .fetch_identity(&token)
            .await
            .expect("audience ok");
        assert_eq!(identity.username, "vasu");
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let (server, idp) = idp_server().await;
        let token = idp.mint(json!({ "sub": "abc", "aud": "some-other-client" }));
        let err = provider(&server.uri(), Some("expected-audience"))
            .fetch_identity(&token)
            .await
            .expect_err("audience");
        assert!(matches!(err, AuthProviderError::Unauthorized));
    }

    #[tokio::test]
    async fn jwks_rotation_refreshes_on_unknown_kid() {
        let server = MockServer::start().await;
        // First key k1 serves discovery; a token signed by k2 forces a refresh.
        let idp1 = TestIdp::new(&server.uri(), "k1");
        let idp2 = TestIdp::new(&server.uri(), "k2");
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(idp1.discovery()))
            .mount(&server)
            .await;
        // JWKS endpoint returns BOTH keys (post-rotation set).
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [ idp1.jwk.clone(), idp2.jwk.clone() ]
            })))
            .mount(&server)
            .await;

        let token = idp2.mint(json!({ "sub": "abc", "preferred_username": "rotated" }));
        let identity = provider(&server.uri(), None)
            .fetch_identity(&token)
            .await
            .expect("rotated identity");
        assert_eq!(identity.username, "rotated");
    }

    #[tokio::test]
    async fn unsigned_or_hs256_token_is_rejected() {
        let (server, _idp) = idp_server().await;

        // Forge an HS256 token claiming the same kid; verification must refuse
        // because the JWK is RSA (algorithm confusion).
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("k1".to_string());
        let now = Utc::now().timestamp();
        let forged = jsonwebtoken::encode(
            &header,
            &json!({ "sub": "attacker", "iss": server.uri(), "exp": now + 300 }),
            &EncodingKey::from_secret(b"public-key-bytes-as-hmac-secret"),
        )
        .expect("forge");

        let err = provider(&server.uri(), None)
            .fetch_identity(&forged)
            .await
            .expect_err("alg confusion");
        assert!(matches!(err, AuthProviderError::Unauthorized));
    }
}
