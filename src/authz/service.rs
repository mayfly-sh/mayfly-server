//! Config-driven authorization.
//!
//! Authorization is **deny-by-default**: an [`Identity`] is allowed only if it
//! matches one of the configured allowlists (user, org, or team). Matching is
//! case-insensitive, since GitHub logins, org logins, and team slugs are not
//! case-sensitive.

use crate::authz::models::{AuthzDecision, Identity};
use crate::config::AccessConfig;

/// Evaluates [`Identity`] values against the configured allowlists.
#[derive(Debug, Clone)]
pub struct AuthzService {
    access: AccessConfig,
}

impl AuthzService {
    /// Build a service from the access configuration.
    pub fn new(access: AccessConfig) -> Self {
        Self { access }
    }

    /// Decide whether `identity` is permitted.
    ///
    /// Order: a user match wins first, then any org match, then any team match;
    /// otherwise the identity is denied.
    pub fn authorize(&self, identity: &Identity) -> AuthzDecision {
        if contains_ci(&self.access.allowed_users, &identity.login) {
            return AuthzDecision::Allow;
        }

        if identity
            .orgs
            .iter()
            .any(|org| contains_ci(&self.access.allowed_orgs, org))
        {
            return AuthzDecision::Allow;
        }

        if identity
            .teams
            .iter()
            .any(|team| contains_ci(&self.access.allowed_teams, team))
        {
            return AuthzDecision::Allow;
        }

        AuthzDecision::Deny {
            reason: format!(
                "'{}' is not in any allowlist (orgs={:?}, teams={:?})",
                identity.login, identity.orgs, identity.teams
            ),
        }
    }
}

/// Case-insensitive membership test.
fn contains_ci(haystack: &[String], needle: &str) -> bool {
    haystack
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(users: &[&str], orgs: &[&str], teams: &[&str]) -> AccessConfig {
        AccessConfig {
            allowed_users: users.iter().map(|s| s.to_string()).collect(),
            allowed_orgs: orgs.iter().map(|s| s.to_string()).collect(),
            allowed_teams: teams.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn allowed_user_is_permitted() {
        let svc = AuthzService::new(access(&["vasugarg"], &[], &[]));
        assert!(svc.authorize(&Identity::new("vasugarg", 1)).is_allowed());
    }

    #[test]
    fn allowed_user_match_is_case_insensitive() {
        let svc = AuthzService::new(access(&["VasuGarg"], &[], &[]));
        assert!(svc.authorize(&Identity::new("vasugarg", 1)).is_allowed());
    }

    #[test]
    fn denied_user_is_rejected() {
        let svc = AuthzService::new(access(&["someone-else"], &[], &[]));
        let decision = svc.authorize(&Identity::new("vasugarg", 1));
        assert!(matches!(decision, AuthzDecision::Deny { .. }));
    }

    #[test]
    fn allowed_org_is_permitted() {
        let svc = AuthzService::new(access(&[], &["acme"], &[]));
        let identity = Identity::new("vasugarg", 1).with_orgs(vec!["acme".to_string()]);
        assert!(svc.authorize(&identity).is_allowed());
    }

    #[test]
    fn denied_org_is_rejected() {
        let svc = AuthzService::new(access(&[], &["acme"], &[]));
        let identity = Identity::new("vasugarg", 1).with_orgs(vec!["other".to_string()]);
        assert!(matches!(svc.authorize(&identity), AuthzDecision::Deny { .. }));
    }

    #[test]
    fn allowed_team_is_permitted() {
        let svc = AuthzService::new(access(&[], &[], &["acme/platform"]));
        let identity = Identity::new("vasugarg", 1).with_teams(vec!["acme/platform".to_string()]);
        assert!(svc.authorize(&identity).is_allowed());
    }

    #[test]
    fn denied_team_is_rejected() {
        let svc = AuthzService::new(access(&[], &[], &["acme/platform"]));
        let identity = Identity::new("vasugarg", 1).with_teams(vec!["acme/interns".to_string()]);
        assert!(matches!(svc.authorize(&identity), AuthzDecision::Deny { .. }));
    }

    #[test]
    fn empty_config_denies_everyone() {
        let svc = AuthzService::new(AccessConfig::default());
        let identity = Identity::new("vasugarg", 1)
            .with_orgs(vec!["acme".to_string()])
            .with_teams(vec!["acme/platform".to_string()]);
        assert!(matches!(svc.authorize(&identity), AuthzDecision::Deny { .. }));
    }
}
