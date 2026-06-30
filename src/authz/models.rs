//! Authorization domain types (provider-neutral).

use std::collections::BTreeMap;

/// The resolved, provider-neutral identity an authorization decision is made
/// against.
///
/// Built by the certificate-issuance/admin flow from the authenticating
/// provider's [`crate::auth::AuthenticatedIdentity`] plus its
/// [`crate::auth::AuthorizationContext`]. GitHub populates `organizations`/
/// `teams`; Keycloak (OIDC) populates `realm`/`groups`/`roles`/`attributes`;
/// `username` is the login (GitHub) or `preferred_username` (OIDC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Provider id that authenticated this identity (e.g. `github`, `keycloak`).
    pub provider: String,
    /// Stable, provider-unique subject (GitHub numeric id, OIDC `sub`).
    pub subject: String,
    /// Human username/login (GitHub login, OIDC `preferred_username`).
    pub username: String,
    /// Email, when available.
    pub email: Option<String>,
    /// Display name, when available.
    pub display_name: Option<String>,
    /// Provider realm/tenant, when applicable (Keycloak realm).
    pub realm: Option<String>,
    /// Organizations the identity belongs to (GitHub orgs).
    pub organizations: Vec<String>,
    /// Teams the identity belongs to (GitHub `org/team`).
    pub teams: Vec<String>,
    /// Groups the identity belongs to (OIDC groups).
    pub groups: Vec<String>,
    /// Roles granted to the identity (OIDC realm roles + `client/role`).
    pub roles: Vec<String>,
    /// Additional string/array attributes (generic OIDC claims).
    pub attributes: BTreeMap<String, Vec<String>>,
}

impl Identity {
    /// Convenience constructor for a username-only identity (no memberships).
    pub fn new(
        provider: impl Into<String>,
        subject: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            subject: subject.into(),
            username: username.into(),
            email: None,
            display_name: None,
            realm: None,
            organizations: Vec::new(),
            teams: Vec::new(),
            groups: Vec::new(),
            roles: Vec::new(),
            attributes: BTreeMap::new(),
        }
    }

    /// Attach org memberships (builder style).
    #[must_use]
    pub fn with_orgs(mut self, orgs: Vec<String>) -> Self {
        self.organizations = orgs;
        self
    }

    /// Attach team memberships (builder style).
    #[must_use]
    pub fn with_teams(mut self, teams: Vec<String>) -> Self {
        self.teams = teams;
        self
    }

    /// Attach group memberships (builder style).
    #[must_use]
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = groups;
        self
    }

    /// Attach roles (builder style).
    #[must_use]
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }
}

/// The outcome of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    /// The identity is permitted.
    Allow,
    /// The identity is denied, with a server-side explanation.
    Deny {
        /// Human-readable reason (logged/audited, not returned verbatim).
        reason: String,
    },
}

impl AuthzDecision {
    /// `true` when access is permitted.
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthzDecision::Allow)
    }
}
