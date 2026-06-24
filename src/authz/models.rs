//! Authorization domain types.

/// The resolved GitHub identity an authorization decision is made against.
///
/// Built by the certificate-issuance flow after the GitHub user (and, when the
/// configuration requires them, org/team memberships) have been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// GitHub login (username).
    pub login: String,
    /// Numeric GitHub user id.
    pub github_id: u64,
    /// Org logins the identity belongs to.
    pub orgs: Vec<String>,
    /// Teams the identity belongs to, formatted `org-login/team-slug`.
    pub teams: Vec<String>,
}

impl Identity {
    /// Convenience constructor for a login-only identity (no org/team data).
    pub fn new(login: impl Into<String>, github_id: u64) -> Self {
        Self {
            login: login.into(),
            github_id,
            orgs: Vec::new(),
            teams: Vec::new(),
        }
    }

    /// Attach org memberships (builder style).
    #[must_use]
    pub fn with_orgs(mut self, orgs: Vec<String>) -> Self {
        self.orgs = orgs;
        self
    }

    /// Attach team memberships (builder style).
    #[must_use]
    pub fn with_teams(mut self, teams: Vec<String>) -> Self {
        self.teams = teams;
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
