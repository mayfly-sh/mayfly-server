//! GitHub [`AuthenticationProvider`] adapter.
//!
//! Wraps the existing [`crate::github::GitHubClient`] so GitHub authenticates
//! through the same provider abstraction as every other provider. All GitHub
//! HTTP still happens inside the injected client, keeping it mockable.

use std::sync::Arc;

use async_trait::async_trait;

use crate::auth::provider::{
    AuthProviderError, AuthenticatedIdentity, AuthenticationProvider, AuthorizationContext,
    AuthorizationNeeds, DeviceAuthorization, DeviceTokenOutcome, ProviderKind, ProviderMetadata,
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

    /// Fetch GitHub org/team membership, but only when the policy references them
    /// (avoids extra API calls and the `read:org` scope for user-only
    /// allowlists). Membership-lookup failures fail closed (treated as none),
    /// which is safe under deny-by-default authorization.
    async fn resolve_authorization(
        &self,
        access_token: &str,
        _identity: &AuthenticatedIdentity,
        needs: &AuthorizationNeeds,
    ) -> Result<AuthorizationContext, AuthProviderError> {
        let organizations = if needs.organizations {
            fetch_or_empty(self.client.get_user_orgs(access_token).await, "orgs")
        } else {
            Vec::new()
        };
        let teams = if needs.teams {
            fetch_or_empty(self.client.get_user_teams(access_token).await, "teams")
        } else {
            Vec::new()
        };
        Ok(AuthorizationContext {
            organizations,
            teams,
            ..AuthorizationContext::default()
        })
    }
}

/// Use a successful org/team lookup, or treat a failure as "no memberships".
fn fetch_or_empty(
    result: Result<Vec<String>, crate::github::GitHubError>,
    what: &str,
) -> Vec<String> {
    match result {
        Ok(values) => values,
        Err(err) => {
            tracing::warn!(
                error = %err,
                membership = what,
                "failed to resolve GitHub membership; treating as none for authorization",
            );
            Vec::new()
        }
    }
}
