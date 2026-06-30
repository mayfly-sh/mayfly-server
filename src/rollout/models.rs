//! Serializable DTOs for the fleet rollout console (013D / ADR-0025).
//!
//! These are presentation-neutral *views* assembled by [`super::service`] from
//! existing subsystems (the machine registry, the CA generation counter, and the
//! append-only audit log). Nothing here is persisted, and nothing carries a
//! secret — only fingerprints, generations, liveness, and sanitized audit
//! `reason` strings ever appear.

use serde::Serialize;

/// A rollout health verdict. Severity order: `Failed` > `Blocked` > `Degraded`
/// > `Healthy` (see ADR-0025).
pub const HEALTH_HEALTHY: &str = "Healthy";
/// The rollout is incomplete but still progressing.
pub const HEALTH_DEGRADED: &str = "Degraded";
/// The rollout is incomplete and cannot progress without operator action.
pub const HEALTH_BLOCKED: &str = "Blocked";
/// A published bundle failed signature verification on at least one agent.
pub const HEALTH_FAILED: &str = "Failed";

/// The most recent failed bundle-apply attempt attributed to a machine.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MachineFailure {
    /// Audit event type (`bundle.rollback` or `bundle.signature_failed`).
    pub event_type: String,
    /// Generation the agent attempted to apply, if recorded.
    pub generation: Option<i64>,
    /// Sanitized, non-secret reason the agent reported, if any.
    pub reason: Option<String>,
    /// RFC 3339 instant the failure was recorded.
    pub at: String,
}

/// One machine's position in the current rollout.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MachineRollout {
    /// Server-issued machine identifier.
    pub machine_id: String,
    /// Reported hostname.
    pub hostname: String,
    /// Lifecycle status (`active`/`disabled`/`revoked`/`pending`).
    pub status: String,
    /// Derived liveness (`ONLINE`/`STALE`/`OFFLINE`).
    pub liveness: String,
    /// Generation the agent last successfully applied, or `null`.
    pub synced_generation: Option<i64>,
    /// The server's current (latest) generation, when a CA is configured.
    pub latest_generation: Option<i64>,
    /// Generation the agent last self-reported via heartbeat.
    pub current_generation: i64,
    /// Whether the agent is on the latest generation.
    pub up_to_date: bool,
    /// How many generations behind latest (0 when up to date).
    pub generations_behind: i64,
    /// Rollout state: `current` | `lagging` | `stuck`.
    pub state: &'static str,
    /// Why the machine is in this state (see [`super::service`] for the taxonomy).
    pub category: &'static str,
    /// Last successful apply instant (RFC 3339), or `null`.
    pub last_sync: Option<String>,
    /// Last heartbeat instant (RFC 3339), or `null`.
    pub last_seen: Option<String>,
    /// The most recent failed apply attributed to this machine, if any.
    pub last_failure: Option<MachineFailure>,
}

/// Active-machine breakdown used by the watch dashboard. The five buckets are
/// mutually exclusive and sum to `active_machines`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct RolloutBreakdown {
    /// Active machines on the latest generation.
    pub healthy: i64,
    /// Lagging active machines whose heartbeat is stale.
    pub stale: i64,
    /// Lagging active machines that are offline.
    pub offline: i64,
    /// Lagging active machines with a recent apply failure.
    pub failed: i64,
    /// Lagging active machines that are online and simply have not pulled yet.
    pub pending: i64,
}

/// Per-generation machine population.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GenerationDetail {
    /// The synced generation.
    pub generation: i64,
    /// Machines currently on this generation.
    pub machines: i64,
    /// Share of all enrolled machines on this generation (0–100, 1 dp).
    pub percentage: f64,
    /// Whether this is the server's latest generation.
    pub is_latest: bool,
}

/// A transparent completion estimate for the current generation.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RolloutEta {
    /// Whether the rollout is already complete.
    pub complete: bool,
    /// Active machines not yet on the latest generation.
    pub remaining: i64,
    /// `bundle.applied` events for the latest generation in the last hour.
    pub applies_last_hour: i64,
    /// Observed apply rate (machines/hour) used for the estimate.
    pub per_hour: f64,
    /// Estimated seconds to completion, or `null` when not estimable.
    pub eta_seconds: Option<i64>,
    /// Estimated completion instant (RFC 3339), or `null`.
    pub estimated_completion: Option<String>,
}

/// A rollout health score with human-readable reasons.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RolloutHealth {
    /// `Healthy` | `Degraded` | `Blocked` | `Failed`.
    pub status: &'static str,
    /// Coarse 0–100 score (100 = complete).
    pub score: u8,
    /// Ordered, human-readable reasons behind the verdict.
    pub reasons: Vec<String>,
}

/// The headline rollout status (`GET /api/v1/admin/rollout`).
#[derive(Debug, Clone, Serialize)]
pub struct RolloutStatus {
    /// Whether bundle distribution is configured (a CA exists).
    pub configured: bool,
    /// The server's latest generation, if a CA is configured.
    pub latest_generation: Option<i64>,
    /// Current bundle fingerprint, if a CA is configured.
    pub bundle_fingerprint: Option<String>,
    /// Total enrolled machines (any status).
    pub total_machines: i64,
    /// Machines whose lifecycle status is `active` (the rollout denominator).
    pub active_machines: i64,
    /// Active machines on the latest generation.
    pub completed: i64,
    /// Active machines not yet on the latest generation.
    pub remaining: i64,
    /// Machines that have never successfully applied any bundle.
    pub never_synced: i64,
    /// Completion percentage over active machines (0–100, 1 dp).
    pub percentage: f64,
    /// Machines seen within the online window.
    pub online: i64,
    /// Machines seen recently but past the online window.
    pub stale: i64,
    /// Machines not seen recently (or never).
    pub offline: i64,
    /// Active-machine breakdown for the watch dashboard.
    pub breakdown: RolloutBreakdown,
    /// Per-generation machine population, ascending by generation.
    pub generations: Vec<GenerationDetail>,
    /// Completion estimate.
    pub eta: RolloutEta,
    /// Health verdict.
    pub health: RolloutHealth,
}

/// Response for `GET /api/v1/admin/rollout/generations`.
#[derive(Debug, Clone, Serialize)]
pub struct GenerationsResponse {
    /// The server's latest generation, if configured.
    pub latest_generation: Option<i64>,
    /// Per-generation machine population.
    pub generations: Vec<GenerationDetail>,
}

/// Response for `GET /api/v1/admin/rollout/machines`.
#[derive(Debug, Clone, Serialize)]
pub struct MachinesResponse {
    /// Number of machines in this view.
    pub count: usize,
    /// The selected machines.
    pub machines: Vec<MachineRollout>,
}

/// One categorized reason a rollout is incomplete, with a recommended action.
#[derive(Debug, Clone, Serialize)]
pub struct ExplainCategory {
    /// Stable category identifier (see [`super::service`]).
    pub category: &'static str,
    /// Number of machines in this category.
    pub count: i64,
    /// Human-readable description of the category.
    pub description: &'static str,
    /// Recommended operator action.
    pub recommendation: &'static str,
    /// A bounded sample of affected machines (hostnames).
    pub machines: Vec<String>,
}

/// Response for `GET /api/v1/admin/rollout/explain`.
#[derive(Debug, Clone, Serialize)]
pub struct RolloutExplanation {
    /// The server's latest generation, if configured.
    pub latest_generation: Option<i64>,
    /// Whether the rollout is complete (no categories when true).
    pub complete: bool,
    /// Active machines not yet on the latest generation.
    pub remaining: i64,
    /// Categories in descending priority, only those with `count > 0`.
    pub categories: Vec<ExplainCategory>,
}

/// One stuck machine plus a concrete remediation.
#[derive(Debug, Clone, Serialize)]
pub struct StuckMachine {
    /// Server-issued machine identifier.
    pub machine_id: String,
    /// Reported hostname.
    pub hostname: String,
    /// The reason category.
    pub category: &'static str,
    /// Generations behind latest.
    pub generations_behind: i64,
    /// Derived liveness.
    pub liveness: String,
    /// Last successful apply instant (RFC 3339), or `null`.
    pub last_sync: Option<String>,
    /// Last heartbeat instant (RFC 3339), or `null`.
    pub last_seen: Option<String>,
    /// The most recent failed apply, if any.
    pub last_failure: Option<MachineFailure>,
    /// Recommended action to unstick the machine.
    pub recommendation: String,
}

/// Response for `GET /api/v1/admin/rollout/stuck`.
#[derive(Debug, Clone, Serialize)]
pub struct StuckReport {
    /// Number of stuck machines.
    pub count: usize,
    /// The stuck machines, most-behind first.
    pub stuck: Vec<StuckMachine>,
}

/// One bundle rollout event, projected from the audit log.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    /// Audit chain position (stable cursor).
    pub position: i64,
    /// RFC 3339 instant.
    pub at: String,
    /// Raw audit event type.
    pub event_type: String,
    /// Normalized outcome (`downloaded`/`applied`/`rolled_back`/`verification_failed`).
    pub outcome: &'static str,
    /// Machine the event concerns, if any.
    pub machine_id: Option<String>,
    /// Generation involved, if recorded.
    pub generation: Option<i64>,
    /// Sanitized, non-secret reason, if any.
    pub reason: Option<String>,
}

/// Response for `GET /api/v1/admin/rollout/timeline`.
#[derive(Debug, Clone, Serialize)]
pub struct RolloutTimeline {
    /// Number of events in this view.
    pub count: usize,
    /// Events, newest first.
    pub events: Vec<TimelineEvent>,
}

/// Adoption history for one generation.
#[derive(Debug, Clone, Serialize)]
pub struct GenerationHistory {
    /// The generation.
    pub generation: i64,
    /// Whether this is the server's latest generation.
    pub is_latest: bool,
    /// Machines currently on this generation.
    pub machines_on_generation: i64,
    /// First time any machine applied this generation (RFC 3339), if known.
    pub first_applied_at: Option<String>,
    /// Most recent time any machine applied this generation (RFC 3339), if known.
    pub last_applied_at: Option<String>,
    /// Total `bundle.applied` events recorded for this generation.
    pub total_applies: i64,
}

/// Response for `GET /api/v1/admin/rollout/history`.
#[derive(Debug, Clone, Serialize)]
pub struct RolloutHistory {
    /// The server's latest generation, if configured.
    pub latest_generation: Option<i64>,
    /// Per-generation adoption history, ascending by generation.
    pub generations: Vec<GenerationHistory>,
}
