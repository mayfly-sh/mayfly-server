//! Keycloak/OIDC access-token claim model and provider-neutral extraction.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::auth::provider::{AuthenticatedIdentity, AuthorizationContext};

use super::PROVIDER_ID;

/// A set of roles, as Keycloak nests them under `realm_access`/`resource_access`.
#[derive(Debug, Default, Deserialize)]
pub struct RoleSet {
    #[serde(default)]
    pub roles: Vec<String>,
}

/// The access-token claims Mayfly reads. Registered claims (`exp`/`nbf`/`iss`/
/// `aud`) are validated by `jsonwebtoken` and need not appear here; everything
/// else is captured for identity + authorization mapping.
#[derive(Debug, Deserialize)]
pub struct KeycloakClaims {
    /// Stable subject id.
    pub sub: String,
    /// Human username.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Email, when present.
    #[serde(default)]
    pub email: Option<String>,
    /// Display name, when present.
    #[serde(default)]
    pub name: Option<String>,
    /// Realm roles.
    #[serde(default)]
    pub realm_access: Option<RoleSet>,
    /// Per-client roles, keyed by client id.
    #[serde(default)]
    pub resource_access: Option<BTreeMap<String, RoleSet>>,
    /// Group memberships (Keycloak group-membership mapper).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Any remaining top-level claims, used for attribute-based authorization.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl KeycloakClaims {
    /// Map the verified claims to a provider-neutral identity.
    pub fn to_identity(&self) -> AuthenticatedIdentity {
        let username = self
            .preferred_username
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| self.sub.clone());
        AuthenticatedIdentity {
            provider: PROVIDER_ID.to_string(),
            subject: self.sub.clone(),
            username,
            email: self.email.clone(),
            display_name: self.name.clone(),
        }
    }

    /// Map the verified claims to provider-neutral authorization facts.
    ///
    /// `issuer` is the canonical OIDC issuer (used to derive the realm).
    pub fn to_authorization(&self, issuer: &str) -> AuthorizationContext {
        AuthorizationContext {
            realm: realm_from_issuer(issuer),
            organizations: Vec::new(),
            teams: Vec::new(),
            groups: normalize_groups(&self.groups),
            roles: self.collect_roles(),
            attributes: self.collect_attributes(),
        }
    }

    /// Realm roles plus client roles as both `client/role` and the bare role,
    /// de-duplicated and case-preserving.
    fn collect_roles(&self) -> Vec<String> {
        let mut roles: Vec<String> = Vec::new();
        let mut push = |r: String| {
            if !r.is_empty() && !roles.iter().any(|x| x.eq_ignore_ascii_case(&r)) {
                roles.push(r);
            }
        };
        if let Some(realm) = &self.realm_access {
            for r in &realm.roles {
                push(r.clone());
            }
        }
        if let Some(resource) = &self.resource_access {
            for (client, set) in resource {
                for r in &set.roles {
                    push(format!("{client}/{r}"));
                    push(r.clone());
                }
            }
        }
        roles
    }

    /// Collect string and array-of-string claims as attributes, bounded in size.
    fn collect_attributes(&self) -> BTreeMap<String, Vec<String>> {
        const MAX_ATTRS: usize = 64;
        const MAX_VALUES: usize = 64;
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, value) in &self.extra {
            if out.len() >= MAX_ATTRS {
                break;
            }
            match value {
                Value::String(s) => {
                    out.insert(key.clone(), vec![s.clone()]);
                }
                Value::Array(items) => {
                    let values: Vec<String> = items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .take(MAX_VALUES)
                        .collect();
                    if !values.is_empty() {
                        out.insert(key.clone(), values);
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// Derive a realm name from a Keycloak issuer URL (`.../realms/<realm>`).
fn realm_from_issuer(issuer: &str) -> Option<String> {
    issuer
        .trim_end_matches('/')
        .rsplit_once("/realms/")
        .map(|(_, realm)| realm.trim_matches('/').to_string())
        .filter(|r| !r.is_empty())
}

/// Strip Keycloak's leading-slash group path convention (`/eng` -> `eng`).
fn normalize_groups(groups: &[String]) -> Vec<String> {
    groups
        .iter()
        .map(|g| g.trim_start_matches('/').to_string())
        .filter(|g| !g.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_is_derived_from_issuer() {
        assert_eq!(
            realm_from_issuer("https://kc.example.com/realms/engineering"),
            Some("engineering".to_string())
        );
        assert_eq!(
            realm_from_issuer("https://kc.example.com/realms/engineering/"),
            Some("engineering".to_string())
        );
        assert_eq!(realm_from_issuer("https://kc.example.com"), None);
    }

    #[test]
    fn groups_are_normalized() {
        let groups = vec!["/eng".to_string(), "ops".to_string(), "/".to_string()];
        assert_eq!(normalize_groups(&groups), vec!["eng", "ops"]);
    }

    #[test]
    fn roles_include_realm_and_client_forms() {
        let claims = KeycloakClaims {
            sub: "s".into(),
            preferred_username: None,
            email: None,
            name: None,
            realm_access: Some(RoleSet {
                roles: vec!["admin".into()],
            }),
            resource_access: Some(BTreeMap::from([(
                "mayfly".to_string(),
                RoleSet {
                    roles: vec!["operator".into()],
                },
            )])),
            groups: vec![],
            extra: serde_json::Map::new(),
        };
        let roles = claims.collect_roles();
        assert!(roles.contains(&"admin".to_string()));
        assert!(roles.contains(&"mayfly/operator".to_string()));
        assert!(roles.contains(&"operator".to_string()));
    }
}
