//! Strongly typed, fail-fast application configuration.
//!
//! Configuration is layered, lowest precedence first:
//! 1. Built-in defaults ([`Config::default`]).
//! 2. A YAML file (e.g. `config.yaml`); missing files are ignored.
//! 3. Environment variables prefixed `MAYFLY_`, using `__` to nest
//!    (e.g. `MAYFLY_SERVER__PORT=9443`).
//!
//! [`Config::load`] composes these layers and then runs
//! [`Config::validate`], so an invalid configuration fails startup with a
//! clear, actionable message rather than at first use.

use std::path::{Path, PathBuf};

use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced while loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration could not be read or deserialized.
    ///
    /// `figment::Error` is large, so it is boxed to keep `ConfigError` (and
    /// every `Result<_, ConfigError>`) small.
    #[error("failed to load configuration: {0}")]
    Load(Box<figment::Error>),

    /// The configuration loaded but failed a semantic validation rule.
    #[error("invalid configuration: {0}")]
    Validation(String),
}

impl From<figment::Error> for ConfigError {
    fn from(err: figment::Error) -> Self {
        ConfigError::Load(Box::new(err))
    }
}

/// Top-level application configuration.
///
/// Note: [`Config::default`] is intentionally *not* a valid runtime
/// configuration — it enables TLS without certificate material so that the
/// secure-by-default posture must be satisfied explicitly. It serves only as
/// the base layer beneath the YAML and environment providers. Always obtain a
/// usable value through [`Config::load`], which validates.
///
/// Unknown keys are rejected (`deny_unknown_fields`) so configuration typos
/// fail fast instead of silently falling back to defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// HTTP server settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Database connection settings.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Logging / telemetry settings.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// HTTP server bind and TLS settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Bind address (e.g. `127.0.0.1`).
    pub host: String,
    /// Bind port.
    pub port: u16,
    /// TLS configuration. HTTPS is the only supported transport.
    #[serde(default)]
    pub tls: TlsConfig,
}

/// TLS material locations.
///
/// Paths are validated for presence at startup; their contents are loaded by
/// the TLS listener when the server binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Whether TLS is enabled. Mayfly only serves HTTPS, so this defaults to
    /// `true`; it exists primarily so tests and tooling can opt out explicitly.
    pub enabled: bool,
    /// PEM-encoded certificate chain path.
    pub cert_path: Option<PathBuf>,
    /// PEM-encoded private key path.
    pub key_path: Option<PathBuf>,
}

/// Database connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// SQLx connection URL (e.g. `sqlite://mayfly.db`).
    pub url: String,
    /// Maximum number of pooled connections.
    pub max_connections: u32,
}

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Output format.
    pub format: LogFormat,
    /// Default tracing filter directive (e.g. `info`, `mayfly_server=debug`).
    ///
    /// Validated at startup. Note that the `RUST_LOG` environment variable, if
    /// set, overrides this value at subscriber-initialization time (see
    /// [`crate::logging::init`]).
    pub level: String,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable, multi-line output for local development.
    Pretty,
    /// Single-line JSON for production log aggregation.
    Json,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8443,
            tls: TlsConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_path: None,
            key_path: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://mayfly.db".to_string(),
            max_connections: 5,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Pretty,
            level: "info".to_string(),
        }
    }
}

impl Config {
    /// Build the layered [`Figment`] without extracting or validating.
    ///
    /// Exposed for tests that want to compose additional providers.
    pub fn figment(path: impl AsRef<Path>) -> Figment {
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Yaml::file(path))
            .merge(Env::prefixed("MAYFLY_").split("__"))
    }

    /// Extract and validate a [`Config`] from an already-composed [`Figment`].
    pub fn from_figment(figment: Figment) -> Result<Self, ConfigError> {
        let config: Config = figment.extract()?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from defaults, the YAML file at `path`, and the
    /// environment, then validate it.
    ///
    /// When `required` is `true`, the file at `path` must exist; a missing file
    /// is a hard error. This prevents an operator-specified configuration path
    /// (e.g. via `MAYFLY_CONFIG`) from being silently ignored, which would
    /// otherwise let the server boot on defaults the operator never intended.
    /// When `required` is `false` (the default search path), a missing file is
    /// tolerated and lower-precedence layers apply.
    pub fn load(path: impl AsRef<Path>, required: bool) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if required && !path.exists() {
            return Err(ConfigError::Validation(format!(
                "configuration file '{}' was specified but does not exist",
                path.display()
            )));
        }
        Self::from_figment(Self::figment(path))
    }

    /// Validate semantic invariants that types alone cannot express.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::Validation(
                "server.port must be between 1 and 65535".to_string(),
            ));
        }

        if self.server.host.trim().is_empty() {
            return Err(ConfigError::Validation(
                "server.host must not be empty".to_string(),
            ));
        }

        if self.database.max_connections == 0 {
            return Err(ConfigError::Validation(
                "database.max_connections must be at least 1".to_string(),
            ));
        }

        if self.database.url.trim().is_empty() {
            return Err(ConfigError::Validation(
                "database.url must not be empty".to_string(),
            ));
        }

        // Validate the log filter eagerly so a typo fails startup, not logging.
        tracing_subscriber::EnvFilter::try_new(&self.logging.level).map_err(|err| {
            ConfigError::Validation(format!(
                "logging.level '{}' is not a valid filter: {err}",
                self.logging.level
            ))
        })?;

        if self.server.tls.enabled {
            if self.server.tls.cert_path.is_none() {
                return Err(ConfigError::Validation(
                    "server.tls.cert_path is required when TLS is enabled".to_string(),
                ));
            }
            if self.server.tls.key_path.is_none() {
                return Err(ConfigError::Validation(
                    "server.tls.key_path is required when TLS is enabled".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn figment_from_yaml(yaml: &str) -> Figment {
        Figment::from(Serialized::defaults(Config::default())).merge(Yaml::string(yaml))
    }

    #[test]
    fn defaults_require_tls_material() {
        // Defaults enable TLS but provide no cert material: must fail fast.
        let err = Config::default().validate().expect_err("should be invalid");
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn yaml_overrides_defaults() {
        let yaml = r#"
server:
  host: "0.0.0.0"
  port: 9443
  tls:
    enabled: false
database:
  url: "sqlite::memory:"
  max_connections: 10
logging:
  format: json
  level: "debug"
"#;
        let config = Config::from_figment(figment_from_yaml(yaml)).expect("valid config");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 9443);
        assert!(!config.server.tls.enabled);
        assert_eq!(config.database.max_connections, 10);
        assert_eq!(config.logging.format, LogFormat::Json);
    }

    #[test]
    fn tls_enabled_without_cert_is_rejected() {
        let yaml = r#"
server:
  tls:
    enabled: true
    key_path: "/etc/mayfly/key.pem"
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("missing cert");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("cert_path")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn zero_port_is_rejected() {
        let yaml = r#"
server:
  port: 0
  tls:
    enabled: false
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("zero port");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("port")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_log_level_is_rejected() {
        let yaml = r#"
server:
  tls:
    enabled: false
logging:
  level: "mayfly=notalevel"
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("bad filter");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("logging.level")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn zero_max_connections_is_rejected() {
        let yaml = r#"
server:
  tls:
    enabled: false
database:
  max_connections: 0
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("zero conns");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("max_connections")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // The Jail closure must return `Result<_, figment::Error>`, whose large
    // Err variant trips `result_large_err`; it is unavoidable test plumbing.
    #[test]
    #[allow(clippy::result_large_err)]
    fn env_overrides_yaml() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
server:
  port: 8443
  tls:
    enabled: false
"#,
            )?;
            jail.set_env("MAYFLY_SERVER__PORT", "9999");
            jail.set_env("MAYFLY_LOGGING__FORMAT", "json");

            let config = Config::load("config.yaml", true).expect("valid config");
            assert_eq!(config.server.port, 9999);
            assert_eq!(config.logging.format, LogFormat::Json);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn missing_optional_file_falls_back_to_defaults_and_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("MAYFLY_SERVER__TLS__ENABLED", "false");
            let config = Config::load("does-not-exist.yaml", false).expect("valid config");
            assert_eq!(config.server.port, 8443);
            assert!(!config.server.tls.enabled);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn missing_required_file_is_rejected() {
        figment::Jail::expect_with(|jail| {
            let _ = jail;
            let err = Config::load("definitely-missing.yaml", true).expect_err("required file");
            match err {
                ConfigError::Validation(msg) => assert!(msg.contains("does not exist")),
                other => panic!("unexpected error: {other:?}"),
            }
            Ok(())
        });
    }

    #[test]
    fn unknown_field_is_rejected() {
        let yaml = r#"
server:
  port: 8443
  bogus_typo: true
  tls:
    enabled: false
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("unknown key");
        assert!(matches!(err, ConfigError::Load(_)));
    }
}
