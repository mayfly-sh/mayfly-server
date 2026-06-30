//! Configuration for the Keycloak / generic-OIDC provider.

/// Default clock-skew leeway, in seconds, applied to `exp`/`nbf` validation.
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 60;

/// Configuration for the Keycloak/OIDC provider.
///
/// Endpoints are taken from the OIDC discovery document; the per-field
/// convention helpers below are only used as a fallback for the device grant
/// when discovery is unavailable. JWT verification always requires discovery
/// (for `jwks_uri` and the canonical `issuer`).
#[derive(Debug, Clone)]
pub struct KeycloakProviderConfig {
    /// Realm base URL, e.g. `https://kc.example.com/realms/engineering`. Used as
    /// the OIDC issuer and the base for `.well-known/openid-configuration`.
    pub issuer_url: String,
    /// OAuth client id.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<String>,
    /// Space-delimited scopes (default `openid profile email`).
    pub scopes: String,
    /// Expected audience (`aud`) for access tokens. When `None`, audience is not
    /// enforced (Keycloak access-token `aud` varies by realm configuration).
    pub audience: Option<String>,
    /// Clock-skew leeway, in seconds, for `exp`/`nbf` validation.
    pub clock_skew_secs: u64,
}

impl KeycloakProviderConfig {
    /// Normalize the issuer URL (no trailing slash).
    pub fn issuer(&self) -> String {
        self.issuer_url.trim_end_matches('/').to_string()
    }

    /// `.well-known` discovery document URL.
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer())
    }

    /// Keycloak convention device-authorization endpoint (discovery fallback).
    pub fn device_endpoint_convention(&self) -> String {
        format!("{}/protocol/openid-connect/auth/device", self.issuer())
    }

    /// Keycloak convention token endpoint (discovery fallback).
    pub fn token_endpoint_convention(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.issuer())
    }
}
