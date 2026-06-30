//! Provider registry: the single place authentication providers are resolved.
//!
//! Resolving by id (with a configured default) replaces provider `match`/`if`
//! chains throughout the codebase. Registering a new provider is one
//! [`ProviderRegistry::register`] call.

use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::provider::{AuthProviderError, AuthenticationProvider, ProviderMetadata};

/// An immutable set of authentication providers with a default selection.
#[derive(Clone)]
pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn AuthenticationProvider>>,
    default_id: String,
}

impl ProviderRegistry {
    /// Create an empty registry whose default selection is `default_id`.
    pub fn new(default_id: impl Into<String>) -> Self {
        Self {
            providers: HashMap::new(),
            default_id: default_id.into(),
        }
    }

    /// Register a provider under its metadata id. A later registration with the
    /// same id replaces the earlier one (last writer wins), which lets `main`
    /// override the default GitHub provider with a configured instance.
    pub fn register(&mut self, provider: Arc<dyn AuthenticationProvider>) {
        let id = provider.metadata().id;
        self.providers.insert(id, provider);
    }

    /// Builder-style [`register`](Self::register).
    #[must_use]
    pub fn with(mut self, provider: Arc<dyn AuthenticationProvider>) -> Self {
        self.register(provider);
        self
    }

    /// The configured default provider id.
    pub fn default_id(&self) -> &str {
        &self.default_id
    }

    /// Look up a provider by exact id.
    pub fn get(&self, id: &str) -> Option<Arc<dyn AuthenticationProvider>> {
        self.providers.get(id).cloned()
    }

    /// Resolve a provider from an optional, client-supplied selector. An empty
    /// or absent selector uses the configured default. An unknown selector is
    /// an error (never silently falls back) so misrouting is visible.
    pub fn resolve(
        &self,
        selector: Option<&str>,
    ) -> Result<Arc<dyn AuthenticationProvider>, AuthProviderError> {
        let id = match selector.map(str::trim) {
            Some(s) if !s.is_empty() => s,
            _ => self.default_id.as_str(),
        };
        self.get(id).ok_or(AuthProviderError::UnknownProvider)
    }

    /// Metadata for all registered providers, sorted by id for deterministic
    /// output.
    pub fn list(&self) -> Vec<ProviderMetadata> {
        let mut out: Vec<ProviderMetadata> =
            self.providers.values().map(|p| p.metadata()).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::{
        AuthenticatedIdentity, DeviceAuthorization, DeviceTokenOutcome, ProviderKind,
    };
    use async_trait::async_trait;

    struct Stub {
        id: &'static str,
    }

    #[async_trait]
    impl AuthenticationProvider for Stub {
        fn metadata(&self) -> ProviderMetadata {
            ProviderMetadata {
                id: self.id.to_string(),
                display_name: self.id.to_string(),
                kind: ProviderKind::OAuth2Device,
            }
        }
        async fn start_device_authorization(
            &self,
        ) -> Result<DeviceAuthorization, AuthProviderError> {
            Ok(DeviceAuthorization {
                device_code: "dc".into(),
                user_code: "uc".into(),
                verification_uri: "https://example".into(),
                expires_in: 900,
                interval: 5,
            })
        }
        async fn poll_device_authorization(
            &self,
            _device_code: &str,
        ) -> Result<DeviceTokenOutcome, AuthProviderError> {
            Ok(DeviceTokenOutcome::Pending)
        }
        async fn fetch_identity(
            &self,
            _access_token: &str,
        ) -> Result<AuthenticatedIdentity, AuthProviderError> {
            Ok(AuthenticatedIdentity {
                provider: self.id.to_string(),
                subject: "1".into(),
                username: "u".into(),
                email: None,
                display_name: None,
            })
        }
    }

    fn registry() -> ProviderRegistry {
        ProviderRegistry::new("github")
            .with(Arc::new(Stub { id: "github" }))
            .with(Arc::new(Stub { id: "keycloak" }))
    }

    #[test]
    fn resolves_default_when_selector_absent_or_empty() {
        let reg = registry();
        assert_eq!(
            reg.resolve(None).unwrap().metadata().id,
            "github".to_string()
        );
        assert_eq!(
            reg.resolve(Some("  ")).unwrap().metadata().id,
            "github".to_string()
        );
    }

    #[test]
    fn resolves_explicit_provider() {
        let reg = registry();
        assert_eq!(
            reg.resolve(Some("keycloak")).unwrap().metadata().id,
            "keycloak".to_string()
        );
    }

    #[test]
    fn unknown_provider_is_error() {
        let reg = registry();
        assert!(matches!(
            reg.resolve(Some("gitlab")),
            Err(AuthProviderError::UnknownProvider)
        ));
    }

    #[test]
    fn list_is_sorted() {
        let ids: Vec<String> = registry().list().into_iter().map(|m| m.id).collect();
        assert_eq!(ids, vec!["github".to_string(), "keycloak".to_string()]);
    }
}
