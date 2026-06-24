//! Deployment environment / run mode.
//!
//! Governs security-sensitive defaults. In particular, [`Environment::Development`]
//! permits auto-generated self-signed TLS certificates, while
//! [`Environment::Production`] requires operator-provided certificate material.
//!
//! The default is [`Environment::Production`] (fail-closed): a binary with no
//! configuration must not silently fall into a developer-only posture.

use serde::{Deserialize, Serialize};

/// The environment Mayfly is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Production: strict, secure-by-default behavior.
    #[default]
    Production,
    /// Development: developer conveniences such as self-signed dev certs.
    Development,
}

impl Environment {
    /// Whether this is the development environment.
    pub fn is_development(self) -> bool {
        matches!(self, Environment::Development)
    }

    /// Whether this is the production environment.
    pub fn is_production(self) -> bool {
        matches!(self, Environment::Production)
    }

    /// Human-readable label used in startup logging.
    pub fn label(self) -> &'static str {
        match self {
            Environment::Production => "Production",
            Environment::Development => "Development",
        }
    }
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_production() {
        assert_eq!(Environment::default(), Environment::Production);
    }

    #[test]
    fn deserializes_lowercase() {
        let dev: Environment = serde_json::from_str("\"development\"").expect("dev");
        let prod: Environment = serde_json::from_str("\"production\"").expect("prod");
        assert_eq!(dev, Environment::Development);
        assert_eq!(prod, Environment::Production);
    }

    #[test]
    fn predicates_and_label() {
        assert!(Environment::Development.is_development());
        assert!(Environment::Production.is_production());
        assert_eq!(Environment::Development.label(), "Development");
    }
}
