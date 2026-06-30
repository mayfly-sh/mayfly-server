//! The fleet rollout service (013D / ADR-0025).
//!
//! [`RolloutService`] is a *read-only composition* over three existing
//! subsystems — it introduces no persistence and no write path:
//!
//! - the machine registry ([`MachineAdminService`]) for per-machine views,
//! - the CA generation counter ([`crate::ca::CaManager`]) for "latest", and
//! - the append-only audit log ([`crate::audit`]) for bundle apply outcomes
//!   (`bundle.applied` / `bundle.rollback` / `bundle.signature_failed`).
//!
//! It loads one [`RolloutService`] snapshot per request and derives every view
//! ([`RolloutStatus`], [`RolloutHealth`], [`RolloutExplanation`], …) from it, so
//! a single set of inputs produces internally-consistent answers.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::Value;
use sqlx::SqlitePool;

use crate::audit::{AuditEntry, AuditQuery, AuditService, Order};
use crate::ca::CaManager;
use crate::errors::AuditError;
use crate::machines::{
    LivenessStatus, MachineAdminService, MachineFilter, MachineStatus, MachineView,
};
use crate::rollout::models::*;

/// Window over which a failed apply is considered "recent" for attribution.
const FAILURE_WINDOW_HOURS: i64 = 24;
/// Window used to estimate the apply rate for the ETA.
const ETA_WINDOW_SECONDS: i64 = 3600;
/// Upper bound on the recent `bundle.*` event scan that backs failure/ETA logic.
const BUNDLE_EVENT_SCAN: i64 = 1000;
/// Upper bound on `bundle.applied` events scanned for generation history.
const HISTORY_EVENT_SCAN: i64 = 1000;
/// Default and maximum timeline page sizes.
pub const TIMELINE_DEFAULT_LIMIT: i64 = 50;
/// Maximum timeline page size.
pub const TIMELINE_MAX_LIMIT: i64 = 500;
/// Maximum sample machines listed per `explain` category.
const EXPLAIN_SAMPLE: usize = 10;

// Machine rollout-state categories. One is assigned to every not-up-to-date
// machine, in the priority order documented on [`categorize`].
const CAT_UP_TO_DATE: &str = "up_to_date";
const CAT_REVOKED: &str = "revoked_machine";
const CAT_DISABLED: &str = "disabled_machine";
const CAT_VERIFICATION: &str = "bundle_verification_failure";
const CAT_HELPER: &str = "helper_failure";
const CAT_OFFLINE: &str = "offline";
const CAT_STALE: &str = "heartbeat_stale";
const CAT_MISMATCH: &str = "generation_mismatch";

/// Errors loading a rollout snapshot.
#[derive(Debug, thiserror::Error)]
pub enum RolloutError {
    /// A machine-registry query failed.
    #[error("rollout database error")]
    Database(#[from] sqlx::Error),
    /// An audit-log read failed.
    #[error("rollout audit error")]
    Audit(#[from] AuditError),
}

impl From<RolloutError> for crate::errors::ApiError {
    fn from(err: RolloutError) -> Self {
        match err {
            RolloutError::Database(e) => Self::internal(anyhow::Error::new(e)),
            RolloutError::Audit(e) => Self::internal(anyhow::Error::new(e)),
        }
    }
}

/// An internally-tracked recent failure (kept with its parsed timestamp so a
/// failure that predates a later successful sync can be ignored).
#[derive(Debug, Clone)]
struct RecentFailure {
    failure: MachineFailure,
    at: DateTime<Utc>,
}

/// A loaded, read-only rollout snapshot.
pub struct RolloutService {
    machines: Vec<MachineView>,
    latest_generation: Option<i64>,
    bundle_fingerprint: Option<String>,
    configured: bool,
    /// machine_id → most recent failure (rollback/signature_failed) in window.
    failures: HashMap<String, RecentFailure>,
    /// Recent `bundle.*` events, newest first (bounded scan).
    bundle_events: Vec<AuditEntry>,
    now: DateTime<Utc>,
}

impl RolloutService {
    /// Load a snapshot from the registry, the CA, and the audit log.
    pub async fn load(
        pool: SqlitePool,
        ca: Option<Arc<CaManager>>,
        configured: bool,
        audit: &AuditService,
        now: DateTime<Utc>,
    ) -> Result<Self, RolloutError> {
        let latest_generation = ca.as_ref().map(|c| i64::from(c.generation()));
        let bundle_fingerprint = ca.as_ref().map(|c| c.bundle_fingerprint());

        let machines = MachineAdminService::sqlite(pool)
            .list(now, latest_generation, &MachineFilter::default())
            .await?;

        let since = now - Duration::hours(FAILURE_WINDOW_HOURS);
        let page = audit
            .search(&AuditQuery {
                event_prefix: Some("bundle.".to_string()),
                since: Some(since),
                limit: BUNDLE_EVENT_SCAN,
                order: Order::Descending,
                ..AuditQuery::default()
            })
            .await?;
        let bundle_events = page.entries;

        // Most recent failure per machine. Events are newest-first, so the first
        // failure seen for a machine is the most recent one.
        let mut failures: HashMap<String, RecentFailure> = HashMap::new();
        for e in &bundle_events {
            if e.event_type != "bundle.rollback" && e.event_type != "bundle.signature_failed" {
                continue;
            }
            let Some(mid) = event_machine_id(e) else {
                continue;
            };
            failures.entry(mid).or_insert_with(|| RecentFailure {
                failure: MachineFailure {
                    event_type: e.event_type.clone(),
                    generation: meta_i64(&e.metadata, "generation"),
                    reason: meta_string(&e.metadata, "reason"),
                    at: rfc3339(e.recorded_at),
                },
                at: e.recorded_at,
            });
        }

        Ok(Self {
            machines,
            latest_generation,
            bundle_fingerprint,
            configured,
            failures,
            bundle_events,
            now,
        })
    }

    /// The effective recent failure for a machine, ignoring failures that
    /// predate the machine's last successful sync (it has since recovered).
    fn effective_failure(&self, m: &MachineView) -> Option<&MachineFailure> {
        let rf = self.failures.get(&m.machine_id)?;
        if let Some(last_sync) = m.last_sync.as_deref().and_then(parse_rfc3339) {
            if rf.at <= last_sync {
                return None;
            }
        }
        Some(&rf.failure)
    }

    /// Classify a machine into a `(state, category)` pair. Priority for a
    /// not-up-to-date machine: revoked → disabled → verification failure →
    /// helper failure → offline → stale → generation mismatch.
    fn categorize(&self, m: &MachineView) -> (&'static str, &'static str) {
        if m.up_to_date {
            return ("current", CAT_UP_TO_DATE);
        }
        let category = match m.status {
            MachineStatus::Revoked => CAT_REVOKED,
            MachineStatus::Disabled => CAT_DISABLED,
            _ => match self.effective_failure(m).map(|f| f.event_type.as_str()) {
                Some("bundle.signature_failed") => CAT_VERIFICATION,
                Some("bundle.rollback") => CAT_HELPER,
                _ => match m.liveness {
                    LivenessStatus::Offline => CAT_OFFLINE,
                    LivenessStatus::Stale => CAT_STALE,
                    LivenessStatus::Online => CAT_MISMATCH,
                },
            },
        };
        let state = if is_stuck_category(category) {
            "stuck"
        } else {
            "lagging"
        };
        (state, category)
    }

    /// Project one machine into its [`MachineRollout`] view.
    fn machine_rollout(&self, m: &MachineView) -> MachineRollout {
        let (state, category) = self.categorize(m);
        MachineRollout {
            machine_id: m.machine_id.clone(),
            hostname: m.hostname.clone(),
            status: m.status.as_str().to_string(),
            liveness: liveness_str(m.liveness).to_string(),
            synced_generation: m.synced_generation,
            latest_generation: m.latest_generation,
            current_generation: m.current_generation,
            up_to_date: m.up_to_date,
            generations_behind: generations_behind(m),
            state,
            category,
            last_sync: m.last_sync.clone(),
            last_seen: m.last_seen.clone(),
            last_failure: self.effective_failure(m).cloned(),
        }
    }

    /// All machines as rollout views (registry order: by hostname).
    pub fn machines(&self) -> Vec<MachineRollout> {
        self.machines
            .iter()
            .map(|m| self.machine_rollout(m))
            .collect()
    }

    /// Machines filtered by rollout state (`all`/`current`/`lagging`/`stuck`)
    /// and/or an exact synced generation.
    pub fn machines_filtered(&self, state: &str, generation: Option<i64>) -> Vec<MachineRollout> {
        self.machines()
            .into_iter()
            .filter(|m| match state {
                "current" => m.state == "current",
                // `lagging` includes everything not on the latest generation
                // (stuck machines are a strict subset).
                "lagging" => m.state != "current",
                "stuck" => m.state == "stuck",
                _ => true,
            })
            .filter(|m| match generation {
                Some(g) => m.synced_generation == Some(g),
                None => true,
            })
            .collect()
    }

    /// Active machines (the rollout denominator).
    fn active(&self) -> impl Iterator<Item = &MachineView> {
        self.machines
            .iter()
            .filter(|m| m.status == MachineStatus::Active)
    }

    /// The active-machine breakdown for the watch dashboard.
    pub fn breakdown(&self) -> RolloutBreakdown {
        let mut b = RolloutBreakdown::default();
        for m in self.active() {
            if m.up_to_date {
                b.healthy += 1;
            } else if self.effective_failure(m).is_some() {
                b.failed += 1;
            } else {
                match m.liveness {
                    LivenessStatus::Offline => b.offline += 1,
                    LivenessStatus::Stale => b.stale += 1,
                    LivenessStatus::Online => b.pending += 1,
                }
            }
        }
        b
    }

    /// Per-generation machine population (all machines that have ever synced).
    pub fn generations(&self) -> Vec<GenerationDetail> {
        let total = self.machines.len() as i64;
        let mut counts: BTreeMap<i64, i64> = BTreeMap::new();
        for m in &self.machines {
            if let Some(g) = m.synced_generation {
                *counts.entry(g).or_insert(0) += 1;
            }
        }
        counts
            .into_iter()
            .map(|(generation, machines)| GenerationDetail {
                generation,
                machines,
                percentage: percentage(machines, total),
                is_latest: Some(generation) == self.latest_generation,
            })
            .collect()
    }

    /// The headline status.
    pub fn status(&self) -> RolloutStatus {
        let total_machines = self.machines.len() as i64;
        let active_machines = self.active().count() as i64;
        let completed = self.active().filter(|m| m.up_to_date).count() as i64;
        let remaining = active_machines - completed;
        let never_synced = self
            .machines
            .iter()
            .filter(|m| m.synced_generation.is_none())
            .count() as i64;

        let mut online = 0;
        let mut stale = 0;
        let mut offline = 0;
        for m in &self.machines {
            match m.liveness {
                LivenessStatus::Online => online += 1,
                LivenessStatus::Stale => stale += 1,
                LivenessStatus::Offline => offline += 1,
            }
        }

        RolloutStatus {
            configured: self.configured,
            latest_generation: self.latest_generation,
            bundle_fingerprint: self.bundle_fingerprint.clone(),
            total_machines,
            active_machines,
            completed,
            remaining,
            never_synced,
            percentage: percentage(completed, active_machines),
            online,
            stale,
            offline,
            breakdown: self.breakdown(),
            generations: self.generations(),
            eta: self.eta(),
            health: self.health(),
        }
    }

    /// Count `bundle.applied` events for the latest generation in the ETA window.
    fn applies_last_hour(&self) -> i64 {
        let cutoff = self.now - Duration::seconds(ETA_WINDOW_SECONDS);
        self.bundle_events
            .iter()
            .filter(|e| e.event_type == "bundle.applied")
            .filter(|e| e.recorded_at >= cutoff)
            .filter(
                |e| match (self.latest_generation, meta_i64(&e.metadata, "generation")) {
                    (Some(latest), Some(g)) => g == latest,
                    _ => true,
                },
            )
            .count() as i64
    }

    /// The completion estimate.
    pub fn eta(&self) -> RolloutEta {
        let remaining = (self.active().count() as i64)
            - (self.active().filter(|m| m.up_to_date).count() as i64);
        let applies = self.applies_last_hour();
        let per_hour = applies as f64;
        let complete = remaining <= 0;
        let (eta_seconds, estimated_completion) = if complete || per_hour <= 0.0 {
            (None, None)
        } else {
            let secs = ((remaining as f64) / per_hour * ETA_WINDOW_SECONDS as f64).ceil() as i64;
            (
                Some(secs),
                Some(rfc3339(self.now + Duration::seconds(secs))),
            )
        };
        RolloutEta {
            complete,
            remaining: remaining.max(0),
            applies_last_hour: applies,
            per_hour,
            eta_seconds,
            estimated_completion,
        }
    }

    /// The health verdict.
    pub fn health(&self) -> RolloutHealth {
        let active: Vec<&MachineView> = self.active().collect();
        let active_count = active.len() as i64;
        let completed = active.iter().filter(|m| m.up_to_date).count() as i64;
        let remaining = active_count - completed;
        let pct = percentage(completed, active_count);

        let signature_failures = self
            .bundle_events
            .iter()
            .filter(|e| e.event_type == "bundle.signature_failed")
            .count();
        let rollbacks = self
            .bundle_events
            .iter()
            .filter(|e| e.event_type == "bundle.rollback")
            .count();

        let lagging: Vec<&&MachineView> = active.iter().filter(|m| !m.up_to_date).collect();
        let reachable_lagging = lagging
            .iter()
            .filter(|m| matches!(m.liveness, LivenessStatus::Online | LivenessStatus::Stale))
            .count();

        let mut reasons = Vec::new();
        let (status, score) = if signature_failures > 0 {
            reasons.push(format!(
                "{signature_failures} bundle signature verification failure(s) in the last {FAILURE_WINDOW_HOURS}h — agents rejected an untrusted bundle"
            ));
            (HEALTH_FAILED, (pct * 0.5) as u8)
        } else if active_count == 0 {
            reasons.push("no active machines enrolled".to_string());
            (HEALTH_HEALTHY, 100)
        } else if remaining == 0 {
            reasons.push(format!(
                "all {active_count} active machine(s) are on the latest generation"
            ));
            (HEALTH_HEALTHY, 100)
        } else if reachable_lagging == 0 {
            reasons.push(format!(
                "{remaining} machine(s) behind and none are reachable (offline); rollout cannot progress without intervention"
            ));
            (HEALTH_BLOCKED, pct as u8)
        } else {
            reasons.push(format!(
                "{completed}/{active_count} active machine(s) on the latest generation ({remaining} behind)"
            ));
            if rollbacks > 0 {
                reasons.push(format!(
                    "{rollbacks} bundle rollback(s) (apply/reload failures) in the last {FAILURE_WINDOW_HOURS}h"
                ));
            }
            (HEALTH_DEGRADED, pct as u8)
        };

        RolloutHealth {
            status,
            score,
            reasons,
        }
    }

    /// Categorized explanation of why the rollout is incomplete.
    pub fn explain(&self) -> RolloutExplanation {
        let remaining = (self.active().count() as i64)
            - (self.active().filter(|m| m.up_to_date).count() as i64);

        // Bucket every not-up-to-date machine (any status) by category.
        let mut buckets: HashMap<&'static str, Vec<String>> = HashMap::new();
        for m in &self.machines {
            if m.up_to_date {
                continue;
            }
            let (_, category) = self.categorize(m);
            buckets
                .entry(category)
                .or_default()
                .push(m.hostname.clone());
        }

        // Emit in fixed priority order so output is stable.
        let order = [
            CAT_VERIFICATION,
            CAT_HELPER,
            CAT_OFFLINE,
            CAT_STALE,
            CAT_DISABLED,
            CAT_REVOKED,
            CAT_MISMATCH,
        ];
        let mut categories = Vec::new();
        for cat in order {
            if let Some(hosts) = buckets.get(cat) {
                if hosts.is_empty() {
                    continue;
                }
                let mut sample = hosts.clone();
                sample.sort();
                sample.truncate(EXPLAIN_SAMPLE);
                categories.push(ExplainCategory {
                    category: cat,
                    count: hosts.len() as i64,
                    description: category_description(cat),
                    recommendation: category_recommendation(cat),
                    machines: sample,
                });
            }
        }

        RolloutExplanation {
            latest_generation: self.latest_generation,
            complete: remaining <= 0,
            remaining: remaining.max(0),
            categories,
        }
    }

    /// Stuck machines (a strict subset of lagging) with remediation, most-behind
    /// first.
    pub fn stuck(&self) -> StuckReport {
        let mut stuck: Vec<StuckMachine> = self
            .machines
            .iter()
            .filter_map(|m| {
                let (state, category) = self.categorize(m);
                if state != "stuck" {
                    return None;
                }
                Some(StuckMachine {
                    machine_id: m.machine_id.clone(),
                    hostname: m.hostname.clone(),
                    category,
                    generations_behind: generations_behind(m),
                    liveness: liveness_str(m.liveness).to_string(),
                    last_sync: m.last_sync.clone(),
                    last_seen: m.last_seen.clone(),
                    last_failure: self.effective_failure(m).cloned(),
                    recommendation: category_recommendation(category).to_string(),
                })
            })
            .collect();
        stuck.sort_by(|a, b| {
            b.generations_behind
                .cmp(&a.generations_behind)
                .then_with(|| a.hostname.cmp(&b.hostname))
        });
        StuckReport {
            count: stuck.len(),
            stuck,
        }
    }

    /// The bundle rollout timeline (most recent first), backed by a dedicated
    /// audit scan so it can page deeper than the snapshot's failure window.
    pub async fn timeline(
        &self,
        audit: &AuditService,
        limit: i64,
    ) -> Result<RolloutTimeline, RolloutError> {
        let limit = limit.clamp(1, TIMELINE_MAX_LIMIT);
        let page = audit
            .search(&AuditQuery {
                event_prefix: Some("bundle.".to_string()),
                limit,
                order: Order::Descending,
                ..AuditQuery::default()
            })
            .await?;
        let events: Vec<TimelineEvent> = page
            .entries
            .into_iter()
            .map(|e| TimelineEvent {
                position: e.chain_position,
                at: rfc3339(e.recorded_at),
                outcome: outcome_of(&e.event_type),
                machine_id: event_machine_id(&e),
                generation: meta_i64(&e.metadata, "generation"),
                reason: meta_string(&e.metadata, "reason"),
                event_type: e.event_type,
            })
            .collect();
        Ok(RolloutTimeline {
            count: events.len(),
            events,
        })
    }

    /// Generation adoption history (ascending), combining the current population
    /// with `bundle.applied` timestamps from the audit log.
    pub async fn history(&self, audit: &AuditService) -> Result<RolloutHistory, RolloutError> {
        // Current population per generation.
        let mut population: BTreeMap<i64, i64> = BTreeMap::new();
        for m in &self.machines {
            if let Some(g) = m.synced_generation {
                *population.entry(g).or_insert(0) += 1;
            }
        }

        // Apply history per generation from the audit log (ascending in time).
        let page = audit
            .search(&AuditQuery {
                event_type: Some("bundle.applied".to_string()),
                limit: HISTORY_EVENT_SCAN,
                order: Order::Ascending,
                ..AuditQuery::default()
            })
            .await?;

        struct Agg {
            first: DateTime<Utc>,
            last: DateTime<Utc>,
            total: i64,
        }
        let mut applies: BTreeMap<i64, Agg> = BTreeMap::new();
        for e in &page.entries {
            let Some(gen) = meta_i64(&e.metadata, "generation") else {
                continue;
            };
            applies
                .entry(gen)
                .and_modify(|a| {
                    a.first = a.first.min(e.recorded_at);
                    a.last = a.last.max(e.recorded_at);
                    a.total += 1;
                })
                .or_insert(Agg {
                    first: e.recorded_at,
                    last: e.recorded_at,
                    total: 1,
                });
        }

        // Union of generations seen in either source.
        let mut gens: Vec<i64> = population.keys().copied().collect();
        for g in applies.keys() {
            if !gens.contains(g) {
                gens.push(*g);
            }
        }
        gens.sort_unstable();

        let generations = gens
            .into_iter()
            .map(|g| {
                let agg = applies.get(&g);
                GenerationHistory {
                    generation: g,
                    is_latest: Some(g) == self.latest_generation,
                    machines_on_generation: population.get(&g).copied().unwrap_or(0),
                    first_applied_at: agg.map(|a| rfc3339(a.first)),
                    last_applied_at: agg.map(|a| rfc3339(a.last)),
                    total_applies: agg.map(|a| a.total).unwrap_or(0),
                }
            })
            .collect();

        Ok(RolloutHistory {
            latest_generation: self.latest_generation,
            generations,
        })
    }
}

// --- free helpers ---------------------------------------------------------

fn is_stuck_category(category: &str) -> bool {
    matches!(
        category,
        CAT_OFFLINE | CAT_VERIFICATION | CAT_HELPER | CAT_DISABLED | CAT_REVOKED
    )
}

fn category_description(category: &str) -> &'static str {
    match category {
        CAT_VERIFICATION => "agent rejected the bundle signature (untrusted signing key)",
        CAT_HELPER => "agent rolled back after a failed sshd reload",
        CAT_OFFLINE => "no recent heartbeat; the host appears down",
        CAT_STALE => "heartbeats are arriving late",
        CAT_DISABLED => "machine is administratively disabled",
        CAT_REVOKED => "machine is revoked and will not receive bundles",
        CAT_MISMATCH => "online but has not pulled the latest generation yet",
        _ => "unknown",
    }
}

fn category_recommendation(category: &str) -> &'static str {
    match category {
        CAT_VERIFICATION => {
            "Verify the pinned bundle signing key matches the server; re-enroll the machine if the key was rotated."
        }
        CAT_HELPER => {
            "Inspect agent logs (journalctl -u mayfly-agent) and the host's sshd config; the previous bundle was restored."
        }
        CAT_OFFLINE => {
            "Ensure the host is powered on and mayfly-agent is running (systemctl status mayfly-agent)."
        }
        CAT_STALE => "Check network/agent health; the machine should converge on its next sync.",
        CAT_DISABLED => {
            "Enable the machine (mayfly machine enable <id>) if it should receive rollouts."
        }
        CAT_REVOKED => {
            "Remove the machine (mayfly machine delete <id>) or re-enroll a replacement."
        }
        CAT_MISMATCH => "No action needed; it should converge on its next sync interval.",
        _ => "Investigate the machine state.",
    }
}

fn outcome_of(event_type: &str) -> &'static str {
    match event_type {
        "bundle.downloaded" => "downloaded",
        "bundle.applied" => "applied",
        "bundle.rollback" => "rolled_back",
        "bundle.signature_failed" => "verification_failed",
        _ => "other",
    }
}

fn liveness_str(l: LivenessStatus) -> &'static str {
    match l {
        LivenessStatus::Online => "ONLINE",
        LivenessStatus::Stale => "STALE",
        LivenessStatus::Offline => "OFFLINE",
    }
}

fn generations_behind(m: &MachineView) -> i64 {
    match (m.synced_generation, m.latest_generation) {
        (Some(s), Some(l)) => (l - s).max(0),
        (None, Some(l)) => l.max(0),
        _ => 0,
    }
}

fn percentage(part: i64, whole: i64) -> f64 {
    if whole <= 0 {
        return 0.0;
    }
    let pct = (part as f64) * 100.0 / (whole as f64);
    (pct * 10.0).round() / 10.0
}

fn event_machine_id(e: &AuditEntry) -> Option<String> {
    e.subject
        .clone()
        .or_else(|| meta_string(&e.metadata, "machine_id"))
}

fn meta_string(metadata: &Value, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn meta_i64(metadata: &Value, key: &str) -> Option<i64> {
    metadata.get(key).and_then(Value::as_i64)
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::db;
    use crate::machines::repository::{HeartbeatUpdate, MachineRepository};
    use crate::machines::{MachineStatus, NewMachine, SqliteMachineRepository};
    use chrono::TimeZone;

    const PASS: &str = "rollout-test-pass";

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, 0).unwrap() + Duration::seconds(secs)
    }

    fn new_machine(suffix: &str, status: MachineStatus) -> NewMachine {
        NewMachine {
            machine_id: format!("srv_{suffix}"),
            hostname: format!("host-{suffix}"),
            public_key: format!("ssh-ed25519 AAAA{suffix}"),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            agent_version: "0.1.0".to_string(),
            status,
            enrolled_at: at(0),
        }
    }

    /// Build a fleet: `a` synced to latest+online, `b` lagging+online,
    /// `c` lagging+offline, `d` disabled+lagging. Latest generation = 3.
    async fn fixture() -> (SqlitePool, AuditService) {
        let pool = db::connect(":memory:").await.expect("db");
        let repo = SqliteMachineRepository;
        let mut conn = pool.acquire().await.expect("conn");
        for (s, st) in [
            ("a", MachineStatus::Active),
            ("b", MachineStatus::Active),
            ("c", MachineStatus::Active),
            ("d", MachineStatus::Disabled),
        ] {
            repo.insert(&mut conn, &new_machine(s, st))
                .await
                .expect("insert");
        }
        // a, b, c are online (seen "now"); set synced generations directly.
        for (id, gen) in [("srv_a", 3i64), ("srv_b", 2), ("srv_c", 2), ("srv_d", 1)] {
            repo.update_last_seen(
                &mut conn,
                &HeartbeatUpdate {
                    machine_id: id,
                    now: at(0),
                    agent_version: "0.1.0",
                    ip: Some("10.0.0.1"),
                    current_generation: gen,
                },
            )
            .await
            .expect("hb");
            sqlx::query(
                "UPDATE machines SET synced_generation = ?, last_sync = ? WHERE machine_id = ?",
            )
            .bind(gen)
            .bind(at(0).to_rfc3339())
            .bind(id)
            .execute(&pool)
            .await
            .expect("sync");
        }
        // c is offline: push last_seen far into the past.
        sqlx::query("UPDATE machines SET last_seen = ? WHERE machine_id = ?")
            .bind(at(-100_000).to_rfc3339())
            .bind("srv_c")
            .execute(&pool)
            .await
            .expect("offline");

        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(at(0)));
        let audit = AuditService::from_pool(pool.clone(), clock);
        (pool, audit)
    }

    async fn ca(now: DateTime<Utc>, gens: u32) -> Arc<CaManager> {
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now));
        let mgr = CaManager::in_memory(PASS, Arc::new(crate::ca::OsRandom), clock)
            .await
            .expect("mgr");
        // Each generate bumps the generation counter.
        for i in 0..gens {
            mgr.generate(&format!("ca-{i}"), PASS).await.expect("ca");
        }
        Arc::new(mgr)
    }

    use crate::clock::Clock;

    async fn loaded() -> RolloutService {
        let (pool, audit) = fixture().await;
        let ca = ca(at(0), 3).await;
        RolloutService::load(pool, Some(ca), true, &audit, at(0))
            .await
            .expect("load")
    }

    #[tokio::test]
    async fn status_counts_active_completion() {
        let svc = loaded().await;
        let s = svc.status();
        assert_eq!(s.latest_generation, Some(3));
        assert_eq!(s.total_machines, 4);
        assert_eq!(s.active_machines, 3); // a, b, c (d is disabled)
        assert_eq!(s.completed, 1); // only a
        assert_eq!(s.remaining, 2); // b, c
        assert_eq!(s.percentage, 33.3);
    }

    #[tokio::test]
    async fn breakdown_buckets_are_exclusive_and_sum_to_active() {
        let svc = loaded().await;
        let b = svc.breakdown();
        assert_eq!(b.healthy, 1); // a
        assert_eq!(b.pending, 1); // b online lagging
        assert_eq!(b.offline, 1); // c offline lagging
        assert_eq!(b.healthy + b.stale + b.offline + b.failed + b.pending, 3);
    }

    #[tokio::test]
    async fn health_is_degraded_when_reachable_machines_lag() {
        let svc = loaded().await;
        let h = svc.health();
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert!(!h.reasons.is_empty());
    }

    #[tokio::test]
    async fn explain_categorizes_lagging_machines() {
        let svc = loaded().await;
        let e = svc.explain();
        assert!(!e.complete);
        let cats: Vec<&str> = e.categories.iter().map(|c| c.category).collect();
        assert!(cats.contains(&CAT_OFFLINE)); // c
        assert!(cats.contains(&CAT_MISMATCH)); // b
        assert!(cats.contains(&CAT_DISABLED)); // d
    }

    #[tokio::test]
    async fn stuck_includes_offline_and_disabled_not_online_mismatch() {
        let svc = loaded().await;
        let r = svc.stuck();
        let hosts: Vec<&str> = r.stuck.iter().map(|s| s.hostname.as_str()).collect();
        assert!(hosts.contains(&"host-c")); // offline → stuck
        assert!(hosts.contains(&"host-d")); // disabled → stuck
        assert!(!hosts.contains(&"host-b")); // online mismatch → lagging, not stuck
    }

    #[tokio::test]
    async fn generations_breakdown_is_ascending_with_latest_flag() {
        let svc = loaded().await;
        let g = svc.generations();
        assert_eq!(g.first().map(|d| d.generation), Some(1));
        let latest = g.iter().find(|d| d.is_latest);
        assert_eq!(latest.map(|d| d.generation), Some(3));
    }

    #[tokio::test]
    async fn machines_filter_by_state_and_generation() {
        let svc = loaded().await;
        assert_eq!(svc.machines_filtered("current", None).len(), 1); // a
        assert_eq!(svc.machines_filtered("stuck", None).len(), 2); // c, d
        assert_eq!(svc.machines_filtered("all", Some(2)).len(), 2); // b, c synced gen 2
    }
}
