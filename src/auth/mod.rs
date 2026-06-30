//! Provider-agnostic authentication framework.
//!
//! Authentication is expressed entirely in terms of [`AuthenticationProvider`]
//! and resolved through a [`ProviderRegistry`]. GitHub and Keycloak are two
//! implementations; future providers (GitLab, Okta, Azure Entra ID, Google,
//! generic OIDC) are added by implementing the trait and registering them — no
//! changes to handlers or business logic, and no provider `match` statements.
//!
//! Layering mirrors the rest of the server: models/trait (`provider`),
//! selection (`registry`), and concrete implementations (`github`, `keycloak`).

pub mod github;
pub mod keycloak;
pub mod provider;
pub mod registry;

pub use github::GitHubProvider;
pub use keycloak::{KeycloakProvider, KeycloakProviderConfig};
pub use provider::{
    AuthProviderError, AuthenticatedIdentity, AuthenticationProvider, AuthorizationContext,
    AuthorizationNeeds, DeviceAuthorization, DeviceTokenOutcome, OAuthSession, ProviderKind,
    ProviderMetadata,
};
pub use registry::ProviderRegistry;
