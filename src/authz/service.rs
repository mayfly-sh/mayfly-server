//! Config-driven, provider-neutral authorization.
//!
//! Authorization is **deny-by-default**: an [`Identity`] is allowed only if one
//! of its facts matches a configured allowlist — username, GitHub org/team, OIDC
//! group/role, or a generic attribute. Matching is case-insensitive (usernames,
//! org/team slugs, group/role names are not case-sensitive across providers).

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
    /// Order (first match wins): username, then org, team, group, role, and
    /// finally attribute (`key=value`); otherwise the identity is denied.
    pub fn authorize(&self, identity: &Identity) -> AuthzDecision {
        if contains_ci(&self.access.allowed_users, &identity.username) {
            return AuthzDecision::Allow;
        }
        if any_ci(&self.access.allowed_orgs, &identity.organizations) {
            return AuthzDecision::Allow;
        }
        if any_ci(&self.access.allowed_teams, &identity.teams) {
            return AuthzDecision::Allow;
        }
        if any_ci(&self.access.allowed_groups, &identity.groups) {
            return AuthzDecision::Allow;
        }
        if any_ci(&self.access.allowed_roles, &identity.roles) {
            return AuthzDecision::Allow;
        }
        if self.attribute_match(identity) {
            return AuthzDecision::Allow;
        }

        AuthzDecision::Deny {
            reason: format!(
                "'{}' (provider={}) is not in any allowlist (orgs={:?}, teams={:?}, groups={:?}, roles={:?})",
                identity.username,
                identity.provider,
                identity.organizations,
                identity.teams,
                identity.groups,
                identity.roles,
            ),
        }
    }

    /// Match `allowed_attributes` (`key=value`) against the identity attributes,
    /// case-insensitively on both key and value.
    fn attribute_match(&self, identity: &Identity) -> bool {
        if self.access.allowed_attributes.is_empty() || identity.attributes.is_empty() {
            return false;
        }
        self.access.allowed_attributes.iter().any(|entry| {
            let Some((key, value)) = entry.split_once('=') else {
                return false;
            };
            let (key, value) = (key.trim(), value.trim());
            identity
                .attributes
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, values)| values.iter().any(|v| v.eq_ignore_ascii_case(value)))
                .unwrap_or(false)
        })
    }
}

/// Case-insensitive membership test for a single needle.
fn contains_ci(haystack: &[String], needle: &str) -> bool {
    haystack
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(needle))
}

/// Case-insensitive test for any overlap between an allowlist and identity facts.
fn any_ci(allowlist: &[String], facts: &[String]) -> bool {
    facts.iter().any(|fact| contains_ci(allowlist, fact))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access() -> AccessConfig {
        AccessConfig::default()
    }

    fn id(username: &str) -> Identity {
        Identity::new("github", "1", username)
    }

    #[test]
    fn allowed_user_is_permitted() {
        let svc = AuthzService::new(AccessConfig {
            allowed_users: vec!["vasugarg".into()],
            ..access()
        });
        assert!(svc.authorize(&id("vasugarg")).is_allowed());
    }

    #[test]
    fn allowed_user_match_is_case_insensitive() {
        let svc = AuthzService::new(AccessConfig {
            allowed_users: vec!["VasuGarg".into()],
            ..access()
        });
        assert!(svc.authorize(&id("vasugarg")).is_allowed());
    }

    #[test]
    fn denied_user_is_rejected() {
        let svc = AuthzService::new(AccessConfig {
            allowed_users: vec!["someone-else".into()],
            ..access()
        });
        assert!(matches!(
            svc.authorize(&id("vasugarg")),
            AuthzDecision::Deny { .. }
        ));
    }

    #[test]
    fn allowed_org_is_permitted() {
        let svc = AuthzService::new(AccessConfig {
            allowed_orgs: vec!["acme".into()],
            ..access()
        });
        let identity = id("vasugarg").with_orgs(vec!["acme".into()]);
        assert!(svc.authorize(&identity).is_allowed());
    }

    #[test]
    fn allowed_team_is_permitted() {
        let svc = AuthzService::new(AccessConfig {
            allowed_teams: vec!["acme/platform".into()],
            ..access()
        });
        let identity = id("vasugarg").with_teams(vec!["acme/platform".into()]);
        assert!(svc.authorize(&identity).is_allowed());
    }

    #[test]
    fn allowed_group_is_permitted() {
        let svc = AuthzService::new(AccessConfig {
            allowed_groups: vec!["engineering".into()],
            ..access()
        });
        let identity =
            Identity::new("keycloak", "sub", "vasu").with_groups(vec!["engineering".into()]);
        assert!(svc.authorize(&identity).is_allowed());
    }

    #[test]
    fn allowed_role_is_permitted() {
        let svc = AuthzService::new(AccessConfig {
            allowed_roles: vec!["mayfly/operator".into()],
            ..access()
        });
        let identity =
            Identity::new("keycloak", "sub", "vasu").with_roles(vec!["mayfly/operator".into()]);
        assert!(svc.authorize(&identity).is_allowed());
    }

    #[test]
    fn allowed_attribute_is_permitted() {
        let svc = AuthzService::new(AccessConfig {
            allowed_attributes: vec!["department=platform".into()],
            ..access()
        });
        let mut identity = Identity::new("keycloak", "sub", "vasu");
        identity
            .attributes
            .insert("department".into(), vec!["platform".into()]);
        assert!(svc.authorize(&identity).is_allowed());
    }

    #[test]
    fn empty_config_denies_everyone() {
        let svc = AuthzService::new(AccessConfig::default());
        let identity = Identity::new("keycloak", "sub", "vasu")
            .with_orgs(vec!["acme".into()])
            .with_groups(vec!["engineering".into()])
            .with_roles(vec!["admin".into()]);
        assert!(matches!(
            svc.authorize(&identity),
            AuthzDecision::Deny { .. }
        ));
    }
}
