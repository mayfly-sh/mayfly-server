//! GitHub [`AuthenticationProvider`] adapter.
//!
//! Wraps the existing [`crate::github::GitHubClient`] so GitHub authenticates
//! through the same provider abstraction as every other provider. All GitHub
//! HTTP still happens inside the injected client, keeping it mockable.

use std::sync::Arc;

use async_trait::async_trait;

use crate::auth::provider::{
    AuthProviderError, AuthenticatedIdentity, AuthenticationProvider, DeviceAuthorization,
    DeviceTokenOutcome, ProviderKind, ProviderMetadata,
};
use crate::github::GitHubClient;

/// Provider id for GitHub.
pub const PROVIDER_ID: &str = "github";

/// GitHub provider backed by a [`GitHubClient`].
pub struct GitHubProvider {
    client: Arc<dyn GitHubClient>,
}

impl GitHubProvider {
    /// Wrap a GitHub client as an authentication provider.
    pub fn new(client: Arc<dyn GitHubClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AuthenticationProvider for GitHubProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: PROVIDER_ID.to_string(),
            display_name: "GitHub".to_string(),
            kind: ProviderKind::OAuth2Device,
        }
    }

    async fn start_device_authorization(&self) -> Result<DeviceAuthorization, AuthProviderError> {
        Ok(self.client.start_device_flow().await?)
    }

    async fn poll_device_authorization(
        &self,
        device_code: &str,
    ) -> Result<DeviceTokenOutcome, AuthProviderError> {
        Ok(self.client.poll_device_flow(device_code).await?)
    }

    async fn fetch_identity(
        &self,
        access_token: &str,
    ) -> Result<AuthenticatedIdentity, AuthProviderError> {
        let user = self.client.get_user(access_token).await?;
        Ok(AuthenticatedIdentity {
            provider: PROVIDER_ID.to_string(),
            subject: user.id.to_string(),
            username: user.login,
            email: user.email,
            display_name: user.name,
        })
    }
}
