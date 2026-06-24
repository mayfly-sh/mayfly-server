//! Structured logging / tracing initialization.
//!
//! Supports two output formats selected via [`crate::config::LogFormat`]:
//! - `Pretty`: multi-line, colorized output for local development.
//! - `Json`: single-line JSON with span context for production aggregation.
//!
//! Span fields (such as the request id attached by
//! [`crate::request_id`]) are included in every event emitted within that
//! span, providing request correlation across the log stream.

use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

use crate::config::{LogFormat, LoggingConfig};

/// Errors produced while initializing the tracing subscriber.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The configured (or `RUST_LOG`) filter directive was invalid.
    #[error("invalid log filter: {0}")]
    Filter(String),

    /// A global subscriber was already installed.
    #[error("failed to install tracing subscriber: {0}")]
    Init(#[from] tracing_subscriber::util::TryInitError),
}

/// Initialize the global tracing subscriber from configuration.
///
/// The `RUST_LOG` environment variable, when set and non-empty, overrides
/// `config.level` to ease ad-hoc debugging without editing config files.
///
/// This installs a process-global subscriber and must be called at most once;
/// a second call returns [`LoggingError::Init`].
pub fn init(config: &LoggingConfig) -> Result<(), LoggingError> {
    let filter = build_filter(&config.level)?;

    match config.format {
        LogFormat::Json => tracing_subscriber::registry()
            .with(fmt::layer().json().flatten_event(true).with_filter(filter))
            .try_init()?,
        LogFormat::Pretty => tracing_subscriber::registry()
            .with(fmt::layer().pretty().with_filter(filter))
            .try_init()?,
    }

    Ok(())
}

/// Build an [`EnvFilter`], preferring `RUST_LOG` over the configured default.
fn build_filter(level: &str) -> Result<EnvFilter, LoggingError> {
    let directive = match std::env::var("RUST_LOG") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => level.to_string(),
    };

    EnvFilter::try_new(&directive).map_err(|err| LoggingError::Filter(format!("{directive}: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_filter_accepts_valid_directive() {
        assert!(build_filter("info").is_ok());
        assert!(build_filter("mayfly_server=debug,info").is_ok());
    }

    #[test]
    fn build_filter_rejects_invalid_directive() {
        // A directive with an invalid level (`target=level`) is rejected;
        // note that a bare token is accepted by EnvFilter as a target name.
        let err = build_filter("mayfly=notalevel").expect_err("should reject");
        assert!(matches!(err, LoggingError::Filter(_)));
    }
}
