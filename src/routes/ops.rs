//! Operational console admin API (013C / ADR-0024).
//!
//! Read-only operator endpoints that make the CLI the operational console:
//!
//! - `GET /api/v1/admin/audit`        — search the audit log (filter + paginate).
//! - `GET /api/v1/admin/audit/stream` — incremental tail (ascending, `after` cursor).
//! - `GET /api/v1/admin/health`       — operational health rollup.
//! - `GET /api/v1/admin/status`       — lower-level system/cluster status.
//! - `GET /api/v1/admin/metrics`      — API request statistics + timings.
//!
//! Every endpoint authenticates a Bearer token through the provider abstraction
//! and authorizes it deny-by-default. These are **reads**: they are
//! authorization-gated but **not** audited (the CLI polls them in
//! `--watch`/`--follow`, which would flood the append-only hash chain). Only an
//! authorization **denial** appends a fail-closed audit entry, recording the
//! operator identity and privacy-preserving client context. No endpoint here
//! ever returns secrets (tokens, private keys, passphrases, full certificates).

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::{Extension, Json};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::audit::{
    AuditEntry, AuditQuery, NewAuditEntry, Order, RequestAuditContext, ResultFilter,
};
use crate::authz::{AuthzDecision, AuthzError, Identity};
use crate::errors::ApiError;
use crate::machines::{LivenessStatus, MachineAdminService, MachineFilter};
use crate::ops::ApiMetricsSnapshot;
use crate::request_id::RequestId;
use crate::routes::auth::{resolve_identity, BearerToken};
use crate::routes::health::VERSION;
use crate::state::AppState;

/// Default activity window (hours) for health rollups.
const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Bounded scan size when tallying per-provider authentication activity.
const PROVIDER_TALLY_LIMIT: i64 = 1000;

// ---------------------------------------------------------------------------
// Audit search
// ---------------------------------------------------------------------------

/// Query parameters for `GET /api/v1/admin/audit`.
///
/// All optional. `operator`/`username` are aliases for `actor`. `event_type`
/// matches exactly unless it ends with `.` or `*`, in which case it is a prefix
/// (`certificate.` → `certificate.*`).
#[derive(Debug, Default, Deserialize)]
pub struct AuditSearchParams {
    /// Event type (exact, or prefix when ending in `.`/`*`).
    pub event_type: Option<String>,
    /// Actor (operator/username) — case-insensitive.
    pub actor: Option<String>,
    /// Alias for `actor`.
    pub operator: Option<String>,
    /// Alias for `actor`.
    pub username: Option<String>,
    /// Subject (exact).
    pub subject: Option<String>,
    /// Machine selector (matches subject or `metadata.hostname`).
    pub machine: Option<String>,
    /// Provider id (`metadata.provider`).
    pub provider: Option<String>,
    /// Certificate serial (`metadata.serial`).
    pub serial: Option<String>,
    /// Correlation id (`metadata.client.request_id`).
    pub request_id: Option<String>,
    /// `success` | `failure`.
    pub result: Option<String>,
    /// Inclusive lower bound (RFC 3339).
    pub since: Option<String>,
    /// Inclusive upper bound (RFC 3339).
    pub until: Option<String>,
    /// Return entries strictly after this chain position (cursor).
    pub after: Option<i64>,
    /// Return entries strictly before this chain position (cursor).
    pub before: Option<i64>,
    /// Page size (default 50, max 1000).
    pub limit: Option<i64>,
    /// `asc` | `desc` (default `desc`).
    pub order: Option<String>,
}

impl AuditSearchParams {
    /// Convert into a typed [`AuditQuery`], validating enums and timestamps.
    fn into_query(self, default_order: Order) -> Result<AuditQuery, ApiError> {
        let actor = first_non_empty([self.actor, self.operator, self.username]);

        let (event_type, event_prefix) = match non_empty(self.event_type) {
            Some(value) if value.ends_with('.') => (None, Some(value)),
            Some(value) if value.ends_with('*') => {
                (None, Some(value.trim_end_matches('*').to_string()))
            }
            other => (other, None),
        };

        let result = match non_empty(self.result) {
            None => None,
            Some(v) => Some(
                ResultFilter::parse(&v)
                    .ok_or_else(|| ApiError::BadRequest(format!("unknown result '{v}'")))?,
            ),
        };

        let order = match non_empty(self.order).map(|s| s.to_lowercase()) {
            None => default_order,
            Some(v) if v == "asc" || v == "ascending" => Order::Ascending,
            Some(v) if v == "desc" || v == "descending" => Order::Descending,
            Some(v) => return Err(ApiError::BadRequest(format!("unknown order '{v}'"))),
        };

        Ok(AuditQuery {
            event_type,
            event_prefix,
            actor,
            subject: non_empty(self.subject),
            machine: non_empty(self.machine),
            provider: non_empty(self.provider),
            serial: non_empty(self.serial),
            request_id: non_empty(self.request_id),
            result,
            since: parse_time(self.since, "since")?,
            until: parse_time(self.until, "until")?,
            after_position: self.after,
            before_position: self.before,
            limit: self.limit.unwrap_or(crate::audit::query::DEFAULT_LIMIT),
            order,
        })
    }
}

/// A serializable projection of an [`AuditEntry`] for the operator console.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntryView {
    /// 1-based chain position (stable cursor).
    pub position: i64,
    /// Dotted event identifier.
    pub event_type: String,
    /// Who triggered the event.
    pub actor: String,
    /// Target of the action, if any.
    pub subject: Option<String>,
    /// Derived classification: `success` | `failure`.
    pub result: &'static str,
    /// RFC 3339 timestamp.
    pub recorded_at: String,
    /// Structured event metadata (already free of secrets at write time).
    pub metadata: Value,
    /// Hex SHA-256 entry hash (chain integrity).
    pub entry_hash: String,
}

impl AuditEntryView {
    fn from_entry(entry: AuditEntry) -> Self {
        Self {
            position: entry.chain_position,
            result: classify_result(&entry.event_type),
            event_type: entry.event_type,
            actor: entry.actor,
            subject: entry.subject,
            recorded_at: entry
                .recorded_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            metadata: entry.metadata,
            entry_hash: entry.entry_hash,
        }
    }
}

/// Response body for audit search and stream.
#[derive(Debug, Clone, Serialize)]
pub struct AuditSearchResponse {
    /// Matching entries in the requested order.
    pub entries: Vec<AuditEntryView>,
    /// Number of entries in this page.
    pub count: usize,
    /// Whether more entries match beyond this page.
    pub has_more: bool,
    /// The highest chain position in this page (cursor for `--follow`).
    pub last_position: Option<i64>,
    /// The order this page was returned in (`asc`|`desc`).
    pub order: &'static str,
}

/// `GET /api/v1/admin/audit` — search the audit log.
pub async fn audit_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<AuditSearchParams>,
    BearerToken(token): BearerToken,
) -> Result<Json<AuditSearchResponse>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ops.audit").await?;
    let query = params.into_query(Order::Descending)?;
    run_search(&state, query).await.map(Json)
}

/// `GET /api/v1/admin/audit/stream` — incremental ascending tail.
pub async fn audit_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    Query(params): Query<AuditSearchParams>,
    BearerToken(token): BearerToken,
) -> Result<Json<AuditSearchResponse>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ops.audit_stream").await?;
    // Streaming always ascends so a client can advance an `after` cursor.
    let query = params.into_query(Order::Ascending)?;
    run_search(&state, query).await.map(Json)
}

async fn run_search(state: &AppState, query: AuditQuery) -> Result<AuditSearchResponse, ApiError> {
    let order = query.order;
    let page = state
        .audit()
        .search(&query)
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
    let entries: Vec<AuditEntryView> = page
        .entries
        .into_iter()
        .map(AuditEntryView::from_entry)
        .collect();
    let last_position = entries.iter().map(|e| e.position).max();
    Ok(AuditSearchResponse {
        count: entries.len(),
        has_more: page.has_more,
        last_position,
        order: match order {
            Order::Ascending => "asc",
            Order::Descending => "desc",
        },
        entries,
    })
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// Operational health rollup for `GET /api/v1/admin/health`.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    /// `ok` | `degraded` | `unconfigured`.
    pub status: &'static str,
    /// Server crate version.
    pub version: &'static str,
    /// Seconds since startup.
    pub uptime_seconds: u64,
    /// Fleet machine health.
    pub machines: MachineHealth,
    /// Certificate activity in the recent window.
    pub certificates: CertificateActivity,
    /// Authentication activity in the recent window.
    pub authentication: AuthActivity,
    /// CA trust bundle status.
    pub bundle: BundleHealth,
    /// Audit chain health.
    pub audit: AuditHealth,
    /// Activity window used for the counts above (hours).
    pub window_hours: i64,
}

/// Fleet machine health.
#[derive(Debug, Clone, Serialize)]
pub struct MachineHealth {
    /// Total enrolled machines.
    pub total: i64,
    /// Machines seen within the online window.
    pub online: i64,
    /// Machines seen recently but past the online window.
    pub stale: i64,
    /// Machines not seen recently (or never).
    pub offline: i64,
    /// Latest CA generation, if a CA is configured.
    pub latest_generation: Option<i64>,
    /// Percentage of machines on the latest generation (0–100).
    pub rollout_percentage: f64,
    /// Machines not yet on the latest generation.
    pub behind: i64,
}

/// Certificate issuance activity.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateActivity {
    /// Certificates issued in the window.
    pub issued: i64,
    /// Certificate requests denied in the window.
    pub denied: i64,
}

/// Authentication activity, with a per-provider breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct AuthActivity {
    /// Total authentication events in the window.
    pub total: i64,
    /// Per-provider authentication counts (bounded scan).
    pub by_provider: Vec<ProviderStat>,
}

/// Per-provider authentication count.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderStat {
    /// Provider id.
    pub provider: String,
    /// Authentication events attributed to the provider in the window.
    pub authentications: i64,
}

/// CA trust bundle status.
#[derive(Debug, Clone, Serialize)]
pub struct BundleHealth {
    /// Whether bundle distribution is configured (CA + signer present).
    pub configured: bool,
    /// Current bundle generation, if a CA is configured.
    pub generation: Option<i64>,
    /// Current bundle fingerprint, if a CA is configured.
    pub fingerprint: Option<String>,
}

/// Audit chain health.
#[derive(Debug, Clone, Serialize)]
pub struct AuditHealth {
    /// Number of entries in the chain.
    pub entries: i64,
    /// Whether the full chain verified.
    pub verified: bool,
    /// Latest chain position, if any.
    pub chain_position: Option<i64>,
}

/// `GET /api/v1/admin/health` — operational health rollup.
pub async fn health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<HealthReport>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ops.health").await?;
    let now = state.clock().now();
    let window_start = now - chrono::TimeDelta::hours(DEFAULT_WINDOW_HOURS);

    let machines = machine_health(&state, now).await?;
    let bundle = bundle_health(&state);
    let audit = audit_health(&state).await?;
    let certificates = certificate_activity(&state, window_start).await?;
    let authentication = auth_activity(&state, window_start).await?;

    // Overall status: unconfigured when no CA; degraded when the chain is broken
    // or any machine is offline while a fleet exists; otherwise ok.
    let status = if !bundle.configured {
        "unconfigured"
    } else if !audit.verified || machines.offline > 0 {
        "degraded"
    } else {
        "ok"
    };

    Ok(Json(HealthReport {
        status,
        version: VERSION,
        uptime_seconds: crate::routes::health::uptime_seconds(&state),
        machines,
        certificates,
        authentication,
        bundle,
        audit,
        window_hours: DEFAULT_WINDOW_HOURS,
    }))
}

async fn machine_health(state: &AppState, now: DateTime<Utc>) -> Result<MachineHealth, ApiError> {
    let latest_generation = state.ca().map(|ca| i64::from(ca.generation()));

    // Prefer the bundle service's fleet status (it computes rollout %); fall back
    // to a liveness count when bundle distribution is not configured.
    if let Some(service) = state.bundle_service() {
        let fleet = service
            .fleet_status(now)
            .await
            .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
        let on_latest: i64 = fleet
            .generations
            .iter()
            .filter(|g| g.generation == i64::from(fleet.latest_generation))
            .map(|g| g.count)
            .sum();
        let behind = (fleet.total_machines - on_latest).max(0);
        return Ok(MachineHealth {
            total: fleet.total_machines,
            online: fleet.online,
            stale: fleet.stale,
            offline: fleet.offline,
            latest_generation: Some(i64::from(fleet.latest_generation)),
            rollout_percentage: fleet.rollout_percentage,
            behind,
        });
    }

    let service = MachineAdminService::sqlite(state.db().clone());
    let views = service
        .list(now, latest_generation, &MachineFilter::default())
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
    let mut online = 0;
    let mut stale = 0;
    let mut offline = 0;
    for v in &views {
        match v.liveness {
            LivenessStatus::Online => online += 1,
            LivenessStatus::Stale => stale += 1,
            LivenessStatus::Offline => offline += 1,
        }
    }
    Ok(MachineHealth {
        total: views.len() as i64,
        online,
        stale,
        offline,
        latest_generation,
        rollout_percentage: 0.0,
        behind: views.len() as i64,
    })
}

fn bundle_health(state: &AppState) -> BundleHealth {
    match state.ca() {
        Some(ca) => BundleHealth {
            configured: state.bundle_signer().is_some(),
            generation: Some(i64::from(ca.generation())),
            fingerprint: Some(ca.bundle_fingerprint()),
        },
        None => BundleHealth {
            configured: false,
            generation: None,
            fingerprint: None,
        },
    }
}

async fn audit_health(state: &AppState) -> Result<AuditHealth, ApiError> {
    let audit = state.audit();
    let tip = audit
        .get_tip()
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
    let verified = audit
        .verify_chain()
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?
        .is_valid();
    Ok(AuditHealth {
        entries: tip.as_ref().map(|t| t.chain_position).unwrap_or(0),
        verified,
        chain_position: tip.map(|t| t.chain_position),
    })
}

async fn certificate_activity(
    state: &AppState,
    since: DateTime<Utc>,
) -> Result<CertificateActivity, ApiError> {
    let issued = count_events(state, "certificate.issued", since).await?;
    let denied = count_events(state, "certificate.denied", since).await?;
    Ok(CertificateActivity { issued, denied })
}

async fn auth_activity(state: &AppState, since: DateTime<Utc>) -> Result<AuthActivity, ApiError> {
    let total = state
        .audit()
        .count(&AuditQuery {
            event_prefix: Some("auth.".to_string()),
            since: Some(since),
            ..AuditQuery::default()
        })
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;

    // Tally providers from a bounded scan of recent auth events.
    let page = state
        .audit()
        .search(&AuditQuery {
            event_prefix: Some("auth.".to_string()),
            since: Some(since),
            limit: PROVIDER_TALLY_LIMIT,
            order: Order::Descending,
            ..AuditQuery::default()
        })
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?;
    let mut counts: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for entry in &page.entries {
        if let Some(provider) = entry.metadata.get("provider").and_then(Value::as_str) {
            *counts.entry(provider.to_string()).or_default() += 1;
        }
    }
    let by_provider = counts
        .into_iter()
        .map(|(provider, authentications)| ProviderStat {
            provider,
            authentications,
        })
        .collect();
    Ok(AuthActivity { total, by_provider })
}

async fn count_events(
    state: &AppState,
    event_type: &str,
    since: DateTime<Utc>,
) -> Result<i64, ApiError> {
    state
        .audit()
        .count(&AuditQuery {
            event_type: Some(event_type.to_string()),
            since: Some(since),
            ..AuditQuery::default()
        })
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::new(e)))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Lower-level system/cluster status for `GET /api/v1/admin/status`.
#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    /// Server crate version.
    pub version: &'static str,
    /// Seconds since startup.
    pub uptime_seconds: u64,
    /// RFC 3339 startup timestamp.
    pub started_at: String,
    /// Database connectivity (`ok`).
    pub database: &'static str,
    /// Certificate authority status.
    pub certificate_authority: CaStatus,
    /// Bundle status.
    pub bundle: BundleHealth,
    /// Audit chain status.
    pub audit: AuditHealth,
    /// Configured authentication providers.
    pub providers: Vec<String>,
    /// API request statistics summary.
    pub api: ApiSummary,
}

/// Certificate authority status.
#[derive(Debug, Clone, Serialize)]
pub struct CaStatus {
    /// Whether a CA manager is configured.
    pub configured: bool,
    /// Total CAs (any state).
    pub total: i64,
    /// Enabled CAs.
    pub enabled: i64,
    /// Current generation.
    pub generation: Option<i64>,
}

/// API request statistics summary (detail at `GET /api/v1/admin/metrics`).
#[derive(Debug, Clone, Serialize)]
pub struct ApiSummary {
    /// Total requests observed since startup.
    pub total_requests: u64,
    /// Number of distinct route keys tracked.
    pub routes_tracked: usize,
}

/// `GET /api/v1/admin/status` — system/cluster status.
pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<StatusReport>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ops.status").await?;

    let certificate_authority = match state.ca() {
        Some(ca) => {
            let records = ca.list();
            CaStatus {
                configured: true,
                total: records.len() as i64,
                enabled: records.iter().filter(|r| r.enabled).count() as i64,
                generation: Some(i64::from(ca.generation())),
            }
        }
        None => CaStatus {
            configured: false,
            total: 0,
            enabled: 0,
            generation: None,
        },
    };

    let snapshot = state.metrics().snapshot();
    let database = if sqlx::query("SELECT 1").execute(state.db()).await.is_ok() {
        "ok"
    } else {
        "error"
    };

    Ok(Json(StatusReport {
        version: VERSION,
        uptime_seconds: crate::routes::health::uptime_seconds(&state),
        started_at: state
            .started_at()
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        database,
        certificate_authority,
        bundle: bundle_health(&state),
        audit: audit_health(&state).await?,
        providers: state.providers().list().into_iter().map(|p| p.id).collect(),
        api: ApiSummary {
            total_requests: snapshot.total_requests,
            routes_tracked: snapshot.routes.len(),
        },
    }))
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// `GET /api/v1/admin/metrics` — API request statistics + timings.
pub async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    BearerToken(token): BearerToken,
) -> Result<Json<ApiMetricsSnapshot>, ApiError> {
    authorize_admin(&state, &headers, &request_id, &token, "ops.metrics").await?;
    Ok(Json(state.metrics().snapshot()))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Classify an event type into `success`/`failure` (mirrors the SQL filter).
fn classify_result(event_type: &str) -> &'static str {
    let lower = event_type.to_lowercase();
    if crate::audit::query::FAILURE_KEYWORDS
        .iter()
        .any(|kw| lower.contains(kw))
    {
        "failure"
    } else {
        "success"
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn first_non_empty<const N: usize>(values: [Option<String>; N]) -> Option<String> {
    values.into_iter().find_map(non_empty)
}

fn parse_time(value: Option<String>, field: &str) -> Result<Option<DateTime<Utc>>, ApiError> {
    match non_empty(value) {
        None => Ok(None),
        Some(v) => DateTime::parse_from_rfc3339(&v)
            .map(|t| Some(t.with_timezone(&Utc)))
            .map_err(|e| ApiError::BadRequest(format!("invalid {field} timestamp '{v}': {e}"))),
    }
}

/// Resolve and authorize an admin caller (deny-by-default), auditing denials
/// with operator identity + privacy-preserving client context. Reads that pass
/// authorization are intentionally not audited.
async fn authorize_admin(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &RequestId,
    token: &str,
    action: &str,
) -> Result<Identity, ApiError> {
    let identity = resolve_identity(state, None, token).await?;
    if let AuthzDecision::Deny { reason } = state.authz().authorize(&identity) {
        tracing::warn!(
            target: "mayfly::security",
            actor = %identity.username,
            action = %action,
            reason = %reason,
            "ops admin action denied",
        );
        let client = RequestAuditContext::from_headers(
            headers,
            Some(request_id.as_str()),
            state.clock().now(),
        )
        .with_provider(identity.provider.clone())
        .to_value();
        state
            .audit()
            .append_audit_event(
                NewAuditEntry::new("ops.admin_denied", identity.username.clone())
                    .with_subject(action.to_string())
                    .with_metadata(json!({
                        "reason": reason,
                        "provider": identity.provider,
                        "subject": identity.subject,
                        "client": client,
                    })),
            )
            .await?;
        return Err(AuthzError::Denied { reason }.into());
    }
    Ok(identity)
}
