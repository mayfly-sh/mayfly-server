//! Enterprise client context for audit records.
//!
//! Every authenticated request carries privacy-preserving client metadata in
//! `X-Mayfly-*` headers (set by the CLI's `ClientContext`). [`RequestAuditContext`]
//! extracts that metadata, pairs it with server-observed facts (remote/forwarded
//! IP, user agent, server timestamp, request id) and a computed client/server
//! clock drift, and serializes it for embedding in an audit entry's `metadata`.
//!
//! Privacy & security: only non-secret context is recorded. OAuth tokens,
//! refresh tokens, private keys, credential contents, and secret values are
//! never read here or placed in audit metadata. The header names are the wire
//! contract with the CLI and must stay byte-for-byte in sync.

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

// Canonical client-context header names (mirror of the Go CLI's clientcontext).
pub const HEADER_SESSION_ID: &str = "x-mayfly-session-id";
pub const HEADER_CLIENT_VERSION: &str = "x-mayfly-client-version";
pub const HEADER_CLIENT_BUILD: &str = "x-mayfly-client-build";
pub const HEADER_PLATFORM: &str = "x-mayfly-platform";
pub const HEADER_PLATFORM_VERSION: &str = "x-mayfly-platform-version";
pub const HEADER_ARCH: &str = "x-mayfly-arch";
pub const HEADER_HOSTNAME: &str = "x-mayfly-hostname";
pub const HEADER_TIMEZONE: &str = "x-mayfly-timezone";
pub const HEADER_UTC_OFFSET: &str = "x-mayfly-utc-offset";
pub const HEADER_CLIENT_TIME: &str = "x-mayfly-client-timestamp";
pub const HEADER_LOCALE: &str = "x-mayfly-locale";
pub const HEADER_MACHINE_ID: &str = "x-mayfly-machine-id";
pub const HEADER_SECURE_STORAGE: &str = "x-mayfly-secure-storage";
pub const HEADER_SSH_VERSION: &str = "x-mayfly-ssh-version";
pub const HEADER_TERMINAL: &str = "x-mayfly-terminal";
pub const HEADER_CI: &str = "x-mayfly-ci";
pub const HEADER_CONTAINER: &str = "x-mayfly-container";

/// Maximum accepted length for any single client-supplied header value, to
/// bound audit-metadata size and prevent log-bloat abuse.
const MAX_VALUE_LEN: usize = 256;

/// Structured, privacy-preserving client context for an authenticated request.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct RequestAuditContext {
    /// Provider id that authenticated the request (set by the handler).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Server-generated request id (correlation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Client-generated session id (shared across an invocation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Opaque, privacy-preserving stable machine id (hashed client-side).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    /// Best-effort remote IP (forwarded headers; honored only behind a trusted
    /// proxy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Raw forwarded-for chain, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarded_for: Option<String>,
    /// HTTP user agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// CLI semantic version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,
    /// CLI build/commit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_build: Option<String>,
    /// OS/platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// OS/platform version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_version: Option<String>,
    /// CPU architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Client hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// IANA timezone name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// UTC offset, e.g. `+05:30`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utc_offset: Option<String>,
    /// Client local timestamp (RFC3339), as reported by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_timestamp: Option<String>,
    /// Server timestamp when the request was processed (RFC3339).
    pub server_timestamp: String,
    /// Computed drift (server - client) in milliseconds, when both timestamps
    /// are present and parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_drift_ms: Option<i64>,
    /// Client locale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Resolved secure-storage backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_storage: Option<String>,
    /// SSH client version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_version: Option<String>,
    /// Terminal type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
    /// CI environment detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci: Option<bool>,
    /// Container environment detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<bool>,
    /// Certificate id, set by certificate-issuance handlers when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    /// Request processing duration in milliseconds, set when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_duration_ms: Option<i64>,
}

impl RequestAuditContext {
    /// Build the context from request headers, the server-owned request id, and
    /// the server's current time. Header values are sanitized and length-bounded.
    pub fn from_headers(headers: &HeaderMap, request_id: Option<&str>, now: DateTime<Utc>) -> Self {
        let get = |name: &str| header_value(headers, name);
        let client_timestamp = get(HEADER_CLIENT_TIME);
        let clock_drift_ms = client_timestamp
            .as_deref()
            .and_then(parse_rfc3339)
            .map(|client| (now - client).num_milliseconds());

        Self {
            provider: None,
            request_id: request_id.map(sanitize),
            session_id: get(HEADER_SESSION_ID),
            machine_id: get(HEADER_MACHINE_ID),
            remote_ip: remote_ip(headers),
            forwarded_for: header_value(headers, "x-forwarded-for"),
            user_agent: header_value(headers, "user-agent"),
            cli_version: get(HEADER_CLIENT_VERSION),
            cli_build: get(HEADER_CLIENT_BUILD),
            platform: get(HEADER_PLATFORM),
            platform_version: get(HEADER_PLATFORM_VERSION),
            arch: get(HEADER_ARCH),
            hostname: get(HEADER_HOSTNAME),
            timezone: get(HEADER_TIMEZONE),
            utc_offset: get(HEADER_UTC_OFFSET),
            client_timestamp,
            server_timestamp: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            clock_drift_ms,
            locale: get(HEADER_LOCALE),
            secure_storage: get(HEADER_SECURE_STORAGE),
            ssh_version: get(HEADER_SSH_VERSION),
            terminal: get(HEADER_TERMINAL),
            ci: get(HEADER_CI).map(|v| v == "true"),
            container: get(HEADER_CONTAINER).map(|v| v == "true"),
            certificate_id: None,
            request_duration_ms: None,
        }
    }

    /// Set the authenticating provider id.
    #[must_use]
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Serialize to a JSON value for embedding under an audit entry's metadata.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(sanitize)
}

/// Sanitize a header value for safe inclusion in audit metadata: strip control
/// characters (defends against log injection) and bound the length.
fn sanitize(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_VALUE_LEN)
        .collect();
    cleaned
}

/// Best-effort remote IP from forwarding headers. Only meaningful behind a
/// trusted reverse proxy; direct-connection peer IP requires `ConnectInfo`
/// wiring at the listener and is recorded separately when available.
fn remote_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(real) = header_value(headers, "x-real-ip") {
        return Some(real);
    }
    header_value(headers, "x-forwarded-for")
        .and_then(|chain| chain.split(',').next().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 30, 12, 0, 0).unwrap()
    }

    #[test]
    fn extracts_known_headers() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_CLIENT_VERSION, HeaderValue::from_static("1.2.3"));
        h.insert(HEADER_PLATFORM, HeaderValue::from_static("darwin"));
        h.insert(HEADER_ARCH, HeaderValue::from_static("arm64"));
        h.insert(HEADER_SESSION_ID, HeaderValue::from_static("sess-1"));
        h.insert(HEADER_CI, HeaderValue::from_static("true"));
        h.insert("user-agent", HeaderValue::from_static("mayfly-cli/1.2.3"));

        let ctx = RequestAuditContext::from_headers(&h, Some("req-1"), now());
        assert_eq!(ctx.cli_version.as_deref(), Some("1.2.3"));
        assert_eq!(ctx.platform.as_deref(), Some("darwin"));
        assert_eq!(ctx.arch.as_deref(), Some("arm64"));
        assert_eq!(ctx.session_id.as_deref(), Some("sess-1"));
        assert_eq!(ctx.request_id.as_deref(), Some("req-1"));
        assert_eq!(ctx.ci, Some(true));
        assert_eq!(ctx.user_agent.as_deref(), Some("mayfly-cli/1.2.3"));
    }

    #[test]
    fn computes_clock_drift() {
        let mut h = HeaderMap::new();
        // Client 2 seconds behind the server.
        h.insert(
            HEADER_CLIENT_TIME,
            HeaderValue::from_static("2026-06-30T11:59:58Z"),
        );
        let ctx = RequestAuditContext::from_headers(&h, None, now());
        assert_eq!(ctx.clock_drift_ms, Some(2000));
    }

    #[test]
    fn sanitizes_control_characters() {
        let mut h = HeaderMap::new();
        h.insert(
            HEADER_HOSTNAME,
            HeaderValue::from_bytes(b"host\tname").unwrap(),
        );
        let ctx = RequestAuditContext::from_headers(&h, None, now());
        assert_eq!(ctx.hostname.as_deref(), Some("hostname"));
    }

    #[test]
    fn remote_ip_prefers_real_ip() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 2.2.2.2"),
        );
        h.insert("x-real-ip", HeaderValue::from_static("3.3.3.3"));
        let ctx = RequestAuditContext::from_headers(&h, None, now());
        assert_eq!(ctx.remote_ip.as_deref(), Some("3.3.3.3"));
    }

    #[test]
    fn to_value_omits_none_fields() {
        let h = HeaderMap::new();
        let ctx = RequestAuditContext::from_headers(&h, None, now());
        let value = ctx.to_value();
        assert!(value.get("session_id").is_none());
        assert!(value.get("server_timestamp").is_some());
    }
}
