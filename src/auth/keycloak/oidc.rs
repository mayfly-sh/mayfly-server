//! OIDC discovery + JWKS fetching and caching (with key-rotation refresh).

use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::auth::provider::AuthProviderError;

/// Minimum interval between JWKS refreshes triggered by an unknown `kid`.
///
/// Bounds refresh frequency so a flood of tokens with bogus `kid`s cannot turn
/// into a flood of upstream JWKS fetches (a cheap amplification/DoS vector).
const MIN_JWKS_REFRESH: Duration = Duration::from_secs(30);

/// The subset of the OIDC discovery document Mayfly consumes.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    /// Canonical issuer; used as the expected `iss` for token validation.
    pub issuer: String,
    /// Token endpoint (device-grant poll).
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// Device-authorization endpoint (device-grant start).
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    /// JWKS URI (signing keys).
    pub jwks_uri: String,
}

/// Cached JWKS plus the time it was last refreshed.
#[derive(Default)]
pub struct JwksCache {
    set: Option<JwkSet>,
    last_refresh: Option<Instant>,
}

impl JwksCache {
    fn find(&self, kid: &str) -> Option<Jwk> {
        self.set.as_ref().and_then(|s| s.find(kid)).cloned()
    }
}

/// OIDC metadata + key material for one Keycloak realm, cached behind locks.
pub struct OidcCache {
    http: reqwest::Client,
    discovery_url: String,
    discovery: RwLock<Option<OidcDiscovery>>,
    jwks: RwLock<JwksCache>,
}

impl OidcCache {
    /// Build a cache that fetches the discovery document from `discovery_url`.
    pub fn new(http: reqwest::Client, discovery_url: String) -> Self {
        Self {
            http,
            discovery_url,
            discovery: RwLock::new(None),
            jwks: RwLock::new(JwksCache::default()),
        }
    }

    /// Return the discovery document, fetching and caching it on first use.
    pub async fn discovery(&self) -> Result<OidcDiscovery, AuthProviderError> {
        if let Some(d) = self.discovery.read().await.as_ref() {
            return Ok(d.clone());
        }
        let mut guard = self.discovery.write().await;
        if let Some(d) = guard.as_ref() {
            return Ok(d.clone());
        }
        let doc = self.fetch_discovery().await?;
        *guard = Some(doc.clone());
        Ok(doc)
    }

    async fn fetch_discovery(&self) -> Result<OidcDiscovery, AuthProviderError> {
        let resp = self
            .http
            .get(&self.discovery_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| AuthProviderError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthProviderError::UnexpectedStatus {
                status: resp.status().as_u16(),
            });
        }
        resp.json::<OidcDiscovery>()
            .await
            .map_err(|e| AuthProviderError::Decode(format!("discovery document: {e}")))
    }

    /// Resolve a signing key by `kid`, refreshing the JWKS once (rotation) if the
    /// key is unknown — rate-limited by [`MIN_JWKS_REFRESH`].
    pub async fn jwk_for_kid(&self, kid: &str) -> Result<Jwk, AuthProviderError> {
        if let Some(jwk) = self.jwks.read().await.find(kid) {
            return Ok(jwk);
        }

        let jwks_uri = self.discovery().await?.jwks_uri;
        let mut guard = self.jwks.write().await;
        // Re-check: another task may have refreshed while we waited for the lock.
        if let Some(jwk) = guard.find(kid) {
            return Ok(jwk);
        }
        // Rate-limit refreshes for unknown kids once we have a populated cache.
        if let Some(last) = guard.last_refresh {
            if last.elapsed() < MIN_JWKS_REFRESH && guard.set.is_some() {
                return Err(AuthProviderError::Unauthorized);
            }
        }
        let set = self.fetch_jwks(&jwks_uri).await?;
        guard.set = Some(set);
        guard.last_refresh = Some(Instant::now());
        guard.find(kid).ok_or(AuthProviderError::Unauthorized)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet, AuthProviderError> {
        let resp = self
            .http
            .get(jwks_uri)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| AuthProviderError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthProviderError::UnexpectedStatus {
                status: resp.status().as_u16(),
            });
        }
        resp.json::<JwkSet>()
            .await
            .map_err(|e| AuthProviderError::Decode(format!("jwks: {e}")))
    }
}
