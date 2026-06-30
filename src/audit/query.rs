//! Read-only search over the append-only audit log (ADR-0024).
//!
//! This module adds *querying* — never a write path. The append-only triggers,
//! hash chain, and fail-closed append in [`super::repository`]/[`super::service`]
//! are untouched. Filtering uses first-class indexed columns (`event_type`,
//! `actor`, `subject`, `recorded_at`, `chain_position`) plus SQLite
//! `json_extract` for metadata-scoped filters (`provider`, `serial`,
//! `request_id`). Results are bounded by `limit` and paginated with a
//! `chain_position` cursor, so `--follow`/`--watch` polling stays cheap and can
//! never mutate or bloat the chain.

use chrono::{DateTime, SecondsFormat, Utc};

/// Sort order for a search by `chain_position`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Order {
    /// Oldest first (used by streaming/follow).
    Ascending,
    /// Newest first (the default for interactive search).
    #[default]
    Descending,
}

/// Coarse success/failure classification derived from the event type.
///
/// Events whose type contains a failure keyword (`denied`, `failed`,
/// `rejected`, `rollback`, `error`) are failures; everything else is a success.
/// This keeps `result` filterable in SQL without a schema change (ADR-0024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultFilter {
    /// Only successful events.
    Success,
    /// Only failure/denial events.
    Failure,
}

impl ResultFilter {
    /// Parse a case-insensitive result filter value.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "success" | "ok" | "succeeded" => Some(ResultFilter::Success),
            "failure" | "failed" | "fail" | "denied" | "error" => Some(ResultFilter::Failure),
            _ => None,
        }
    }
}

/// SQL `LIKE` fragments (lowercased) that mark an event type as a failure.
pub const FAILURE_KEYWORDS: [&str; 5] = ["denied", "failed", "rejected", "rollback", "error"];

/// Maximum number of entries a single search may return.
pub const MAX_LIMIT: i64 = 1000;
/// Default page size when the caller does not specify a limit.
pub const DEFAULT_LIMIT: i64 = 50;

/// A typed, validated audit search filter.
///
/// All fields are optional; an empty query returns the most recent
/// [`Self::limit`] entries newest-first. String matches on `actor`/`provider`
/// are case-insensitive; `event_type`/`event_prefix` and metadata extracts are
/// matched exactly (case-sensitive) because event identifiers are canonical.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Exact event type (e.g. `certificate.issued`).
    pub event_type: Option<String>,
    /// Event-type prefix (e.g. `certificate.` matches `certificate.*`).
    pub event_prefix: Option<String>,
    /// Actor (operator/username) — case-insensitive exact match.
    pub actor: Option<String>,
    /// Subject (target) — exact match.
    pub subject: Option<String>,
    /// Machine selector — matches `subject` OR `metadata.hostname`.
    pub machine: Option<String>,
    /// Provider id — `metadata.provider`, case-insensitive.
    pub provider: Option<String>,
    /// Certificate serial — `metadata.serial`.
    pub serial: Option<String>,
    /// Correlation id — `metadata.client.request_id`.
    pub request_id: Option<String>,
    /// Derived success/failure classification.
    pub result: Option<ResultFilter>,
    /// Inclusive lower bound on `recorded_at`.
    pub since: Option<DateTime<Utc>>,
    /// Inclusive upper bound on `recorded_at`.
    pub until: Option<DateTime<Utc>>,
    /// Return only entries strictly after this chain position (cursor).
    pub after_position: Option<i64>,
    /// Return only entries strictly before this chain position (cursor).
    pub before_position: Option<i64>,
    /// Maximum entries to return (clamped to `1..=MAX_LIMIT`).
    pub limit: i64,
    /// Sort order by `chain_position`.
    pub order: Order,
}

impl AuditQuery {
    /// A query returning the most recent [`DEFAULT_LIMIT`] entries.
    pub fn recent() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            ..Self::default()
        }
    }

    /// Clamp `limit` into `1..=MAX_LIMIT`, returning the effective value.
    pub fn effective_limit(&self) -> i64 {
        self.limit.clamp(1, MAX_LIMIT)
    }

    /// Render `since` as the canonical millisecond RFC 3339 the column stores,
    /// so the text comparison is well-defined.
    pub(crate) fn since_text(&self) -> Option<String> {
        self.since
            .map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    /// Render `until` as canonical millisecond RFC 3339.
    pub(crate) fn until_text(&self) -> Option<String> {
        self.until
            .map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true))
    }
}

/// One page of audit search results.
#[derive(Debug, Clone)]
pub struct AuditPage {
    /// The matching entries, ordered per [`AuditQuery::order`].
    pub entries: Vec<super::model::AuditEntry>,
    /// Whether more entries match beyond this page (detected via `limit + 1`).
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_filter_parses_case_insensitively() {
        assert_eq!(ResultFilter::parse("SUCCESS"), Some(ResultFilter::Success));
        assert_eq!(
            ResultFilter::parse(" failure "),
            Some(ResultFilter::Failure)
        );
        assert_eq!(ResultFilter::parse("denied"), Some(ResultFilter::Failure));
        assert_eq!(ResultFilter::parse("nonsense"), None);
    }

    #[test]
    fn limit_is_clamped() {
        let mut q = AuditQuery::recent();
        q.limit = 0;
        assert_eq!(q.effective_limit(), 1);
        q.limit = 99_999;
        assert_eq!(q.effective_limit(), MAX_LIMIT);
        q.limit = 25;
        assert_eq!(q.effective_limit(), 25);
    }

    #[test]
    fn default_order_is_descending() {
        assert_eq!(Order::default(), Order::Descending);
    }
}
