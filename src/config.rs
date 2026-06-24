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

use crate::environment::Environment;
use crate::secret::Secret;

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
    /// Deployment environment (defaults to production / fail-closed).
    #[serde(default)]
    pub environment: Environment,
    /// HTTP server settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Database connection settings.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Logging / telemetry settings.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// GitHub OAuth settings (required for authentication).
    #[serde(default)]
    pub github: GithubConfig,
    /// SSH certificate authority settings.
    #[serde(default)]
    pub ca: CaConfig,
    /// Authorization allowlists (deny-by-default).
    #[serde(default)]
    pub access: AccessConfig,
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

/// GitHub OAuth configuration.
///
/// `client_secret` is an `Option<Secret<_>>` so that a *missing* secret stays
/// `null` through Figment's serialized defaults layer (a plain `Secret` would
/// round-trip to the redaction marker `"***"` and defeat fail-fast detection).
/// Both `client_id` and `client_secret` are required by [`Config::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// OAuth app client id (public).
    #[serde(default)]
    pub client_id: String,
    /// OAuth app client secret (sensitive; redacted in all output).
    #[serde(default)]
    pub client_secret: Option<Secret<String>>,
    /// Space-delimited OAuth scopes to request.
    #[serde(default = "default_github_scopes")]
    pub scopes: String,
    /// Base URL for the device/authorization endpoints (overridable for tests
    /// and GitHub Enterprise).
    #[serde(default = "default_github_device_base_url")]
    pub device_base_url: String,
    /// Base URL for the REST API (`/user`).
    #[serde(default = "default_github_api_base_url")]
    pub api_base_url: String,
}

fn default_github_scopes() -> String {
    "read:user user:email".to_string()
}

fn default_github_device_base_url() -> String {
    "https://github.com".to_string()
}

fn default_github_api_base_url() -> String {
    "https://api.github.com".to_string()
}

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: None,
            scopes: default_github_scopes(),
            device_base_url: default_github_device_base_url(),
            api_base_url: default_github_api_base_url(),
        }
    }
}

impl GithubConfig {
    /// The client secret value, or empty string if unset.
    ///
    /// Only call after [`Config::validate`] has confirmed it is present.
    pub fn client_secret_value(&self) -> String {
        self.client_secret
            .as_ref()
            .map(|s| s.expose_secret().clone())
            .unwrap_or_default()
    }
}

/// SSH certificate authority configuration.
///
/// The CA passphrase is never stored in config: only the *name* of the
/// environment variable that holds it is configured, and it is read at startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// Path to the encrypted OpenSSH Ed25519 CA private key.
    pub private_key_path: PathBuf,
    /// Name of the environment variable holding the key's passphrase.
    pub passphrase_env: String,
    /// `key_id` embedded in issued certificates.
    pub key_id: String,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            private_key_path: PathBuf::from("./ca/ca_key"),
            passphrase_env: "CA_PASSPHRASE".to_string(),
            key_id: "mayfly-ca".to_string(),
        }
    }
}

/// Authorization allowlists.
///
/// Access is **deny-by-default**: a caller is permitted only if their GitHub
/// login appears in `allowed_users`, one of their orgs in `allowed_orgs`, or
/// one of their teams (formatted `org-login/team-slug`) in `allowed_teams`.
/// An entirely empty configuration therefore denies everyone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    /// GitHub logins that are always allowed.
    #[serde(default)]
    pub allowed_users: Vec<String>,
    /// GitHub org logins whose members are allowed.
    #[serde(default)]
    pub allowed_orgs: Vec<String>,
    /// GitHub teams (as `org-login/team-slug`) whose members are allowed.
    #[serde(default)]
    pub allowed_teams: Vec<String>,
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

        // In production, TLS material must be provided explicitly. In
        // development, missing paths are tolerated: a self-signed certificate
        // is generated automatically at startup.
        if self.server.tls.enabled && self.environment.is_production() {
            if self.server.tls.cert_path.is_none() {
                return Err(ConfigError::Validation(
                    "server.tls.cert_path is required when TLS is enabled in production"
                        .to_string(),
                ));
            }
            if self.server.tls.key_path.is_none() {
                return Err(ConfigError::Validation(
                    "server.tls.key_path is required when TLS is enabled in production".to_string(),
                ));
            }
        }

        // GitHub OAuth credentials are required for authentication. Checked last
        // so transport/log/TLS misconfigurations surface their own messages
        // first.
        if self.github.client_id.trim().is_empty() {
            return Err(ConfigError::Validation(
                "github.client_id is required".to_string(),
            ));
        }
        let secret_present = self
            .github
            .client_secret
            .as_ref()
            .is_some_and(|s| !s.expose_secret().trim().is_empty());
        if !secret_present {
            return Err(ConfigError::Validation(
                "github.client_secret is required".to_string(),
            ));
        }

        // CA paths/identifiers must be present. The key file's existence,
        // decryptability, and algorithm are verified when the CA is loaded at
        // startup (see `CaService::from_config`), which fails fast.
        if self.ca.private_key_path.as_os_str().is_empty() {
            return Err(ConfigError::Validation(
                "ca.private_key_path must not be empty".to_string(),
            ));
        }
        if self.ca.passphrase_env.trim().is_empty() {
            return Err(ConfigError::Validation(
                "ca.passphrase_env must not be empty".to_string(),
            ));
        }
        // The configuration env layer consumes everything prefixed `MAYFLY_`
        // (see `Config::figment`). A passphrase variable with that prefix would
        // be parsed as an unknown config key and break startup, so reject it
        // with an actionable message rather than failing obscurely later.
        if self
            .ca
            .passphrase_env
            .trim()
            .to_ascii_uppercase()
            .starts_with("MAYFLY_")
        {
            return Err(ConfigError::Validation(format!(
                "ca.passphrase_env '{}' must not start with 'MAYFLY_': that prefix is reserved \
                 for configuration environment variables and would be intercepted by the config \
                 loader. Use a non-prefixed name such as 'CA_PASSPHRASE'.",
                self.ca.passphrase_env
            )));
        }
        if self.ca.key_id.trim().is_empty() {
            return Err(ConfigError::Validation(
                "ca.key_id must not be empty".to_string(),
            ));
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
github:
  client_id: "Iv1.test"
  client_secret: "shh"
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
    fn development_allows_missing_tls_material() {
        let yaml = r#"
environment: development
server:
  tls:
    enabled: true
github:
  client_id: "Iv1.test"
  client_secret: "shh"
"#;
        let config = Config::from_figment(figment_from_yaml(yaml)).expect("valid in dev");
        assert_eq!(config.environment, Environment::Development);
        assert!(config.server.tls.enabled);
        assert!(config.server.tls.cert_path.is_none());
    }

    #[test]
    fn production_requires_tls_material() {
        let yaml = r#"
environment: production
server:
  tls:
    enabled: true
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("prod needs certs");
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
github:
  client_id: "Iv1.test"
  client_secret: "shh"
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
            jail.set_env("MAYFLY_GITHUB__CLIENT_ID", "Iv1.test");
            jail.set_env("MAYFLY_GITHUB__CLIENT_SECRET", "shh");
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

    #[test]
    fn github_credentials_are_required() {
        let yaml = r#"
server:
  tls:
    enabled: false
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("missing github");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("github.client_id")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn github_secret_required_when_only_id_present() {
        let yaml = r#"
server:
  tls:
    enabled: false
github:
  client_id: "Iv1.test"
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("missing secret");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("github.client_secret")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn github_secret_is_redacted_in_debug() {
        let yaml = r#"
server:
  tls:
    enabled: false
github:
  client_id: "Iv1.test"
  client_secret: "top-secret-value"
"#;
        let config = Config::from_figment(figment_from_yaml(yaml)).expect("valid");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("top-secret-value"));
        assert!(rendered.contains("Secret(***)"));
        // But the real value is reachable through the explicit accessor.
        assert_eq!(config.github.client_secret_value(), "top-secret-value");
    }

    #[test]
    fn ca_defaults_are_applied() {
        let yaml = r#"
server:
  tls:
    enabled: false
github:
  client_id: "Iv1.test"
  client_secret: "shh"
"#;
        let config = Config::from_figment(figment_from_yaml(yaml)).expect("valid");
        assert_eq!(config.ca.private_key_path.to_str().unwrap(), "./ca/ca_key");
        assert_eq!(config.ca.passphrase_env, "CA_PASSPHRASE");
        assert_eq!(config.ca.key_id, "mayfly-ca");
    }

    #[test]
    fn mayfly_prefixed_passphrase_env_is_rejected() {
        // A `MAYFLY_`-prefixed passphrase variable would be swallowed by the
        // config env layer; validation must reject it with guidance.
        let yaml = r#"
server:
  tls:
    enabled: false
github:
  client_id: "Iv1.test"
  client_secret: "shh"
ca:
  private_key_path: "./ca/ca_key"
  passphrase_env: "MAYFLY_CA_PASSPHRASE"
  key_id: "mayfly-ca"
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("prefixed env");
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("ca.passphrase_env"));
                assert!(msg.contains("MAYFLY_"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn blank_ca_key_id_is_rejected() {
        let yaml = r#"
server:
  tls:
    enabled: false
github:
  client_id: "Iv1.test"
  client_secret: "shh"
ca:
  private_key_path: "./ca/ca_key"
  passphrase_env: "CA_PASSPHRASE"
  key_id: "   "
"#;
        let err = Config::from_figment(figment_from_yaml(yaml)).expect_err("blank key_id");
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("ca.key_id")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
