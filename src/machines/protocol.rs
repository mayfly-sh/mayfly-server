//! The authenticated agent protocol: heartbeat ingestion and the server
//! registry listing.
//!
//! Handlers stay thin: all SQL and all liveness logic live here. The agent has
//! already been authenticated by the signing middleware before any of this
//! runs, so [`RegistryService`] trusts the `machine_id` it is given but still
//! validates the *contents* of a heartbeat (lengths, ranges) defensively.
//!
//! Liveness ([`LivenessStatus`]) is **always derived** from `last_seen` versus
//! the current time and is never read from, or written to, the database. A
//! client cannot assert that it is "online".

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::machines::repository::{HeartbeatUpdate, MachineRepository, SqliteMachineRepository};
use crate::machines::service::DEFAULT_HEARTBEAT_INTERVAL;

/// A machine is ONLINE if seen within this many seconds.
const ONLINE_WITHIN_SECS: i64 = 120;
/// A machine is STALE if seen within this many seconds (but not ONLINE).
const STALE_WITHIN_SECS: i64 = 600;

/// Default cap on how many machines the listing returns.
pub const DEFAULT_LIST_LIMIT: i64 = 1000;

// Defensive bounds on agent-reported strings/values. The agent is trusted to be
// authentic but not necessarily well-behaved, so we still bound what we store.
const MAX_AGENT_VERSION_LEN: usize = 64;
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_OS_LEN: usize = 64;
const MAX_KERNEL_LEN: usize = 128;
const MAX_IP_LEN: usize = 64;

/// Derived liveness of a machine, computed from `last_seen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LivenessStatus {
    /// Last heartbeat within [`ONLINE_WITHIN_SECS`].
    Online,
    /// Last heartbeat within [`STALE_WITHIN_SECS`] but not ONLINE.
    Stale,
    /// Last heartbeat older than [`STALE_WITHIN_SECS`], or never seen.
    Offline,
}

impl LivenessStatus {
    /// Derive liveness from the last-seen instant relative to `now`.
    ///
    /// A machine never seen (or one whose clock-skew puts `last_seen` in the
    /// future) is treated conservatively: future timestamps count as just-seen
    /// (ONLINE), and absent timestamps are OFFLINE.
    pub fn derive(last_seen: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Self {
        match last_seen {
            None => Self::Offline,
            Some(seen) => {
                let elapsed = (now - seen).num_seconds();
                if elapsed <= ONLINE_WITHIN_SECS {
                    Self::Online
                } else if elapsed <= STALE_WITHIN_SECS {
                    Self::Stale
                } else {
                    Self::Offline
                }
            }
        }
    }
}

/// Request body for `POST /api/v1/agent/heartbeat`.
#[derive(Debug, Clone, Deserialize)]
pub struct HeartbeatRequest {
    /// Agent software version, e.g. `0.1.0`.
    pub agent_version: String,
    /// Self-reported hostname.
    pub hostname: String,
    /// Self-reported operating system, e.g. `linux`.
    pub os: String,
    /// Self-reported kernel version, e.g. `6.12`.
    pub kernel: String,
    /// Self-reported IP address.
    pub ip: String,
    /// Self-reported configuration generation currently applied.
    pub current_generation: i64,
    /// Self-reported process uptime in seconds.
    pub uptime_seconds: i64,
}

/// Response body for a successful heartbeat.
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatResponse {
    /// Always `"ok"` on success.
    pub status: &'static str,
    /// Server's current time (RFC 3339), so the agent can gauge clock skew.
    pub server_time: String,
    /// How many seconds the agent should wait before its next heartbeat.
    pub next_heartbeat_seconds: u32,
}

/// One row of `GET /api/v1/servers`. `status` is derived, never client-supplied.
#[derive(Debug, Clone, Serialize)]
pub struct ServerSummary {
    /// Server-issued machine identifier.
    pub machine_id: String,
    /// Reported hostname.
    pub hostname: String,
    /// Last heartbeat instant (RFC 3339), or `null` if never seen.
    pub last_seen: Option<String>,
    /// Derived liveness (ONLINE / STALE / OFFLINE).
    pub status: LivenessStatus,
    /// Last self-reported IP, or `null`.
    pub ip: Option<String>,
    /// Last self-reported configuration generation.
    pub current_generation: i64,
    /// Last reported agent version.
    pub agent_version: String,
}

/// Errors from the registry service.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A heartbeat field failed validation. The message names the field only.
    #[error("{0}")]
    Validation(String),

    /// The authenticated machine no longer exists (e.g. deleted mid-request).
    #[error("machine not found")]
    UnknownMachine,

    /// A database operation failed.
    #[error("registry database error")]
    Database(#[from] sqlx::Error),
}

impl From<RegistryError> for crate::errors::ApiError {
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::Validation(msg) => Self::BadRequest(msg),
            // The request was authenticated, but the machine vanished before the
            // write (e.g. deleted concurrently). Fail closed as an auth failure.
            RegistryError::UnknownMachine => {
                Self::Unauthorized("request authentication failed".to_string())
            }
            RegistryError::Database(err) => Self::internal(anyhow::Error::new(err)),
        }
    }
}

/// Heartbeat ingestion and registry listing over a [`MachineRepository`].
#[derive(Clone)]
pub struct RegistryService<M: MachineRepository> {
    pool: SqlitePool,
    machines: M,
}

impl RegistryService<SqliteMachineRepository> {
    /// Build the production service backed by SQLite.
    pub fn sqlite(pool: SqlitePool) -> Self {
        Self {
            pool,
            machines: SqliteMachineRepository,
        }
    }
}

impl<M: MachineRepository> RegistryService<M> {
    /// Construct with an explicit repository (for tests).
    pub fn new(pool: SqlitePool, machines: M) -> Self {
        Self { pool, machines }
    }

    /// Record a heartbeat for an already-authenticated `machine_id`.
    ///
    /// Updates `last_seen`, `agent_version`, `ip`, and `current_generation`.
    /// Never changes lifecycle status. `now` comes from the injected clock.
    pub async fn record_heartbeat(
        &self,
        machine_id: &str,
        request: &HeartbeatRequest,
        now: DateTime<Utc>,
    ) -> Result<HeartbeatResponse, RegistryError> {
        let ip = validate_heartbeat(request)?;

        let update = HeartbeatUpdate {
            machine_id,
            now,
            agent_version: request.agent_version.trim(),
            ip: ip.as_deref(),
            current_generation: request.current_generation,
        };

        let mut conn = self.pool.acquire().await?;
        let updated = self.machines.update_last_seen(&mut conn, &update).await?;
        if !updated {
            return Err(RegistryError::UnknownMachine);
        }

        Ok(HeartbeatResponse {
            status: "ok",
            server_time: now.to_rfc3339_opts(SecondsFormat::Millis, true),
            next_heartbeat_seconds: DEFAULT_HEARTBEAT_INTERVAL,
        })
    }

    /// List recent machines with derived liveness, newest activity first.
    pub async fn list_servers(
        &self,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<ServerSummary>, RegistryError> {
        let mut conn = self.pool.acquire().await?;
        let machines = self.machines.list_recent(&mut conn, limit).await?;
        Ok(machines
            .into_iter()
            .map(|m| ServerSummary {
                status: LivenessStatus::derive(m.last_seen, now),
                last_seen: m
                    .last_seen
                    .map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true)),
                machine_id: m.machine_id,
                hostname: m.hostname,
                ip: m.ip,
                current_generation: m.current_generation,
                agent_version: m.agent_version,
            })
            .collect())
    }
}

/// Validate heartbeat contents, returning the normalized IP (`None` if blank).
fn validate_heartbeat(request: &HeartbeatRequest) -> Result<Option<String>, RegistryError> {
    fn check(field: &str, value: &str, max: usize) -> Result<(), RegistryError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(RegistryError::Validation(format!(
                "{field} must not be empty"
            )));
        }
        if trimmed.len() > max {
            return Err(RegistryError::Validation(format!("{field} is too long")));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(RegistryError::Validation(format!(
                "{field} contains control characters"
            )));
        }
        Ok(())
    }

    check(
        "agent_version",
        &request.agent_version,
        MAX_AGENT_VERSION_LEN,
    )?;
    check("hostname", &request.hostname, MAX_HOSTNAME_LEN)?;
    check("os", &request.os, MAX_OS_LEN)?;
    check("kernel", &request.kernel, MAX_KERNEL_LEN)?;

    if request.current_generation < 0 {
        return Err(RegistryError::Validation(
            "current_generation must not be negative".to_string(),
        ));
    }
    if request.uptime_seconds < 0 {
        return Err(RegistryError::Validation(
            "uptime_seconds must not be negative".to_string(),
        ));
    }

    // IP is optional; if present it must be bounded and control-free.
    let ip = request.ip.trim();
    if ip.is_empty() {
        Ok(None)
    } else {
        if ip.len() > MAX_IP_LEN || ip.chars().any(|c| c.is_control()) {
            return Err(RegistryError::Validation("ip is invalid".to_string()));
        }
        Ok(Some(ip.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(unix, 0).expect("valid")
    }

    #[test]
    fn liveness_online_within_two_minutes() {
        let now = at(10_000);
        assert_eq!(
            LivenessStatus::derive(Some(at(10_000)), now),
            LivenessStatus::Online
        );
        assert_eq!(
            LivenessStatus::derive(Some(at(10_000 - 120)), now),
            LivenessStatus::Online
        );
    }

    #[test]
    fn liveness_stale_between_two_and_ten_minutes() {
        let now = at(10_000);
        assert_eq!(
            LivenessStatus::derive(Some(at(10_000 - 121)), now),
            LivenessStatus::Stale
        );
        assert_eq!(
            LivenessStatus::derive(Some(at(10_000 - 600)), now),
            LivenessStatus::Stale
        );
    }

    #[test]
    fn liveness_offline_after_ten_minutes_or_never() {
        let now = at(10_000);
        assert_eq!(
            LivenessStatus::derive(Some(at(10_000 - 601)), now),
            LivenessStatus::Offline
        );
        assert_eq!(LivenessStatus::derive(None, now), LivenessStatus::Offline);
    }

    #[test]
    fn liveness_serializes_uppercase() {
        let json = serde_json::to_string(&LivenessStatus::Online).unwrap();
        assert_eq!(json, "\"ONLINE\"");
        assert_eq!(
            serde_json::to_string(&LivenessStatus::Offline).unwrap(),
            "\"OFFLINE\""
        );
    }

    fn good_request() -> HeartbeatRequest {
        HeartbeatRequest {
            agent_version: "0.1.0".to_string(),
            hostname: "pi-zero".to_string(),
            os: "linux".to_string(),
            kernel: "6.12".to_string(),
            ip: "192.168.1.20".to_string(),
            current_generation: 17,
            uptime_seconds: 123_456,
        }
    }

    #[test]
    fn validate_accepts_good_request_and_normalizes_ip() {
        let ip = validate_heartbeat(&good_request()).unwrap();
        assert_eq!(ip.as_deref(), Some("192.168.1.20"));
    }

    #[test]
    fn validate_blank_ip_becomes_none() {
        let mut req = good_request();
        req.ip = "   ".to_string();
        assert_eq!(validate_heartbeat(&req).unwrap(), None);
    }

    #[test]
    fn validate_rejects_empty_agent_version() {
        let mut req = good_request();
        req.agent_version = "".to_string();
        assert!(matches!(
            validate_heartbeat(&req),
            Err(RegistryError::Validation(_))
        ));
    }

    #[test]
    fn validate_rejects_negative_generation() {
        let mut req = good_request();
        req.current_generation = -1;
        assert!(matches!(
            validate_heartbeat(&req),
            Err(RegistryError::Validation(_))
        ));
    }

    #[test]
    fn validate_rejects_control_characters() {
        let mut req = good_request();
        req.hostname = "bad\u{0}host".to_string();
        assert!(matches!(
            validate_heartbeat(&req),
            Err(RegistryError::Validation(_))
        ));
    }

    #[test]
    fn validate_rejects_overlong_kernel() {
        let mut req = good_request();
        req.kernel = "k".repeat(MAX_KERNEL_LEN + 1);
        assert!(matches!(
            validate_heartbeat(&req),
            Err(RegistryError::Validation(_))
        ));
    }
}
