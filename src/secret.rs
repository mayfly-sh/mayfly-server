//! Redaction wrapper for sensitive configuration values.
//!
//! [`Secret`] hides its contents from `Debug` and `Display` so secrets can
//! never be accidentally written to logs, error messages, or `Debug`-derived
//! output. The inner value is only reachable through the explicit, greppable
//! [`Secret::expose_secret`] accessor.
//!
//! This type is introduced ahead of any secret-bearing configuration (GitHub
//! OAuth client secret, certificate signing keys) so the safe pattern exists
//! before it is needed.

use serde::{Deserialize, Serialize, Serializer};

/// A value whose contents are redacted in all human-readable output.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wrap a sensitive value.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Reveal the underlying secret.
    ///
    /// The deliberately verbose name makes every access site easy to audit.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl<T> std::fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Serializes as the redaction marker, never the underlying value, so a
/// `Secret` accidentally placed in a serialized response cannot leak.
impl<T> Serialize for Secret<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("***")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new("super-secret-token".to_string());
        assert_eq!(format!("{secret:?}"), "Secret(***)");
        assert!(!format!("{secret:?}").contains("super-secret"));
    }

    #[test]
    fn display_is_redacted() {
        let secret = Secret::new("super-secret-token".to_string());
        assert_eq!(format!("{secret}"), "***");
    }

    #[test]
    fn expose_secret_returns_inner() {
        let secret = Secret::new("value".to_string());
        assert_eq!(secret.expose_secret(), "value");
    }

    #[test]
    fn deserializes_transparently() {
        let secret: Secret<String> = serde_json::from_str("\"hunter2\"").expect("deserialize");
        assert_eq!(secret.expose_secret(), "hunter2");
    }

    #[test]
    fn serializes_as_redaction_marker() {
        let secret = Secret::new("hunter2".to_string());
        let json = serde_json::to_string(&secret).expect("serialize");
        assert_eq!(json, "\"***\"");
        assert!(!json.contains("hunter2"));
    }
}
