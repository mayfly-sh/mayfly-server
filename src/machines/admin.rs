//! Machine administration: the operator-facing read + lifecycle service.
//!
//! This is the service layer behind the `admin/machines` HTTP routes. It is the
//! single place that turns persisted [`Machine`] rows into the rich, presentation
//! -neutral [`MachineView`] the CLI renders, applies operator [`MachineFilter`]s,
//! and performs the lifecycle mutations (`approve`/`disable`/`enable`/`revoke`/
//! `delete`). Authorization, auditing, and the privileged enrollment-token mint
//! used by re-enroll/rotate-identity live in the route layer (which owns the
//! audit log and the provider abstraction); this service owns only data access
//! and the [`MachineView`] projection.
//!
//! Liveness and "up to date" are **always derived** here from `last_seen` /
//! `synced_generation` versus the current time and CA generation — never read
//! from a client.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use sqlx::SqlitePool;

use crate::machines::models::{Machine, MachineStatus};
use crate::machines::protocol::LivenessStatus;
use crate::machines::repository::{MachineRepository, SqliteMachineRepository};
use crate::machines::validation::public_key_fingerprint;

/// A rich, presentation-neutral view of one enrolled machine.
///
/// Every field is server-derived or stored; nothing here is trusted from a
/// client. The agent's public key never appears (only its fingerprint, which is
/// the machine's stable identity).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MachineView {
    /// Server-issued machine identifier.
    pub machine_id: String,
    /// Reported hostname.
    pub hostname: String,
    /// Lifecycle status (`pending`/`active`/`disabled`/`revoked`).
    pub status: MachineStatus,
    /// Derived liveness (ONLINE / STALE / OFFLINE) from `last_seen`.
    pub liveness: LivenessStatus,
    /// Reported operating system.
    pub os: String,
    /// Reported CPU architecture.
    pub arch: String,
    /// Reported agent version.
    pub agent_version: String,
    /// Stable machine identity: SHA-256 fingerprint of the enrollment public key.
    pub fingerprint: String,
    /// Last self-reported IP, or `null`.
    pub ip: Option<String>,
    /// Last self-reported configuration generation (from heartbeat).
    pub current_generation: i64,
    /// CA-bundle generation the agent last successfully applied, or `null`.
    pub synced_generation: Option<i64>,
    /// The server's current (latest) CA generation, when a CA is configured.
    pub latest_generation: Option<i64>,
    /// Whether the agent has applied the latest CA generation.
    pub up_to_date: bool,
    /// Fingerprint of the last applied bundle, or `null`.
    pub bundle_fingerprint: Option<String>,
    /// Last heartbeat instant (RFC 3339), or `null`.
    pub last_seen: Option<String>,
    /// Last successful CA-bundle apply instant (RFC 3339), or `null`.
    pub last_sync: Option<String>,
    /// Enrollment instant (RFC 3339).
    pub enrolled_at: String,
}

impl MachineView {
    /// Project a stored [`Machine`] into a view as of `now`, given the server's
    /// current CA `latest_generation` (used to derive `up_to_date`).
    pub fn from_machine(
        machine: &Machine,
        now: DateTime<Utc>,
        latest_generation: Option<i64>,
    ) -> Self {
        let up_to_date = match (machine.synced_generation, latest_generation) {
            (Some(synced), Some(latest)) => synced >= latest,
            _ => false,
        };
        let fmt = |dt: DateTime<Utc>| dt.to_rfc3339_opts(SecondsFormat::Secs, true);
        Self {
            machine_id: machine.machine_id.clone(),
            hostname: machine.hostname.clone(),
            status: machine.status,
            liveness: LivenessStatus::derive(machine.last_seen, now),
            os: machine.os.clone(),
            arch: machine.arch.clone(),
            agent_version: machine.agent_version.clone(),
            fingerprint: public_key_fingerprint(&machine.public_key)
                .unwrap_or_else(|| "unknown".to_string()),
            ip: machine.ip.clone(),
            current_generation: machine.current_generation,
            synced_generation: machine.synced_generation,
            latest_generation,
            up_to_date,
            bundle_fingerprint: machine.bundle_fingerprint.clone(),
            last_seen: machine.last_seen.map(fmt),
            last_sync: machine.last_sync.map(fmt),
            enrolled_at: fmt(machine.enrolled_at),
        }
    }
}

/// Operator-supplied list filters. All are optional and combine with AND; an
/// all-`None` filter matches everything. Matching is case-insensitive for text
/// fields, and `hostname` is a substring match.
#[derive(Debug, Clone, Default)]
pub struct MachineFilter {
    /// Exact lifecycle status.
    pub status: Option<MachineStatus>,
    /// Exact derived liveness.
    pub liveness: Option<LivenessStatus>,
    /// Case-insensitive hostname substring.
    pub hostname: Option<String>,
    /// Matches a machine whose current OR synced generation equals this value.
    pub generation: Option<i64>,
    /// Exact operating system (case-insensitive).
    pub os: Option<String>,
    /// Exact architecture (case-insensitive).
    pub arch: Option<String>,
    /// Exact agent version (case-insensitive).
    pub agent_version: Option<String>,
}

impl MachineFilter {
    /// Whether a view passes every set predicate.
    pub fn matches(&self, view: &MachineView) -> bool {
        if let Some(status) = self.status {
            if view.status != status {
                return false;
            }
        }
        if let Some(liveness) = self.liveness {
            if view.liveness != liveness {
                return false;
            }
        }
        if let Some(hostname) = &self.hostname {
            if !view
                .hostname
                .to_lowercase()
                .contains(&hostname.to_lowercase())
            {
                return false;
            }
        }
        if let Some(generation) = self.generation {
            if view.current_generation != generation && view.synced_generation != Some(generation) {
                return false;
            }
        }
        if let Some(os) = &self.os {
            if !view.os.eq_ignore_ascii_case(os) {
                return false;
            }
        }
        if let Some(arch) = &self.arch {
            if !view.arch.eq_ignore_ascii_case(arch) {
                return false;
            }
        }
        if let Some(agent_version) = &self.agent_version {
            if !view.agent_version.eq_ignore_ascii_case(agent_version) {
                return false;
            }
        }
        true
    }
}

/// Errors from the machine administration service.
#[derive(Debug, thiserror::Error)]
pub enum MachineAdminError {
    /// No machine matched the given identifier.
    #[error("machine '{0}' was not found")]
    NotFound(String),
    /// A database operation failed.
    #[error("machine administration database error")]
    Database(#[from] sqlx::Error),
}

impl From<MachineAdminError> for crate::errors::ApiError {
    fn from(err: MachineAdminError) -> Self {
        match err {
            MachineAdminError::NotFound(id) => {
                Self::NotFound(format!("machine '{id}' was not found"))
            }
            MachineAdminError::Database(err) => Self::internal(anyhow::Error::new(err)),
        }
    }
}

/// Read + lifecycle operations over a [`MachineRepository`].
#[derive(Clone)]
pub struct MachineAdminService<M: MachineRepository = SqliteMachineRepository> {
    pool: SqlitePool,
    machines: M,
}

impl MachineAdminService<SqliteMachineRepository> {
    /// Build the production service backed by SQLite.
    pub fn sqlite(pool: SqlitePool) -> Self {
        Self {
            pool,
            machines: SqliteMachineRepository,
        }
    }
}

impl<M: MachineRepository> MachineAdminService<M> {
    /// Construct with an explicit repository (for tests).
    pub fn new(pool: SqlitePool, machines: M) -> Self {
        Self { pool, machines }
    }

    /// List all machines as views (filtered), ordered by hostname.
    pub async fn list(
        &self,
        now: DateTime<Utc>,
        latest_generation: Option<i64>,
        filter: &MachineFilter,
    ) -> Result<Vec<MachineView>, sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        let machines = self.machines.list_all(&mut conn).await?;
        Ok(machines
            .into_iter()
            .map(|m| MachineView::from_machine(&m, now, latest_generation))
            .filter(|v| filter.matches(v))
            .collect())
    }

    /// Fetch one machine by id, or `None` if it does not exist.
    pub async fn get(
        &self,
        now: DateTime<Utc>,
        latest_generation: Option<i64>,
        machine_id: &str,
    ) -> Result<Option<MachineView>, sqlx::Error> {
        Ok(self
            .find(machine_id)
            .await?
            .map(|m| MachineView::from_machine(&m, now, latest_generation)))
    }

    /// Fetch the raw machine row by id.
    pub async fn find(&self, machine_id: &str) -> Result<Option<Machine>, sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        self.machines.find_by_id(&mut conn, machine_id).await
    }

    /// Set a machine's lifecycle status, returning the updated row.
    pub async fn set_status(
        &self,
        machine_id: &str,
        status: MachineStatus,
        now: DateTime<Utc>,
    ) -> Result<Machine, MachineAdminError> {
        let mut conn = self.pool.acquire().await?;
        let updated = self
            .machines
            .update_status(&mut conn, machine_id, status, now)
            .await?;
        if !updated {
            return Err(MachineAdminError::NotFound(machine_id.to_string()));
        }
        self.machines
            .find_by_id(&mut conn, machine_id)
            .await?
            .ok_or_else(|| MachineAdminError::NotFound(machine_id.to_string()))
    }

    /// Permanently delete a machine, returning the row that was removed (so the
    /// caller can audit its hostname/fingerprint).
    pub async fn delete(&self, machine_id: &str) -> Result<Machine, MachineAdminError> {
        let mut conn = self.pool.acquire().await?;
        let existing = self
            .machines
            .find_by_id(&mut conn, machine_id)
            .await?
            .ok_or_else(|| MachineAdminError::NotFound(machine_id.to_string()))?;
        let deleted = self.machines.delete(&mut conn, machine_id).await?;
        if !deleted {
            return Err(MachineAdminError::NotFound(machine_id.to_string()));
        }
        Ok(existing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::machines::models::NewMachine;
    use crate::machines::repository::HeartbeatUpdate;
    use chrono::TimeZone;

    fn at(seconds: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 24, 12, 0, seconds).unwrap()
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

    async fn seeded() -> MachineAdminService {
        let pool = db::connect(":memory:").await.expect("connect");
        let repo = SqliteMachineRepository;
        let mut conn = pool.acquire().await.expect("conn");
        repo.insert(&mut conn, &new_machine("a", MachineStatus::Active))
            .await
            .expect("insert a");
        repo.insert(&mut conn, &new_machine("b", MachineStatus::Disabled))
            .await
            .expect("insert b");
        // a is seen now (online); b never seen (offline).
        repo.update_last_seen(
            &mut conn,
            &HeartbeatUpdate {
                machine_id: "srv_a",
                now: at(10),
                agent_version: "0.2.0",
                ip: Some("10.0.0.1"),
                current_generation: 5,
            },
        )
        .await
        .expect("hb a");
        drop(conn);
        MachineAdminService::new(pool, repo)
    }

    #[tokio::test]
    async fn lists_all_ordered_by_hostname() {
        let svc = seeded().await;
        let views = svc
            .list(at(15), Some(5), &MachineFilter::default())
            .await
            .expect("list");
        let hosts: Vec<&str> = views.iter().map(|v| v.hostname.as_str()).collect();
        assert_eq!(hosts, vec!["host-a", "host-b"]);
        // a is online and reported gen 5; latest is 5 but synced_generation is
        // still NULL (no successful apply), so it is not "up to date".
        assert_eq!(views[0].liveness, LivenessStatus::Online);
        assert!(!views[0].up_to_date);
        assert_eq!(views[0].current_generation, 5);
        assert_eq!(views[1].liveness, LivenessStatus::Offline);
    }

    #[tokio::test]
    async fn filters_by_status_and_liveness() {
        let svc = seeded().await;
        let active = svc
            .list(
                at(15),
                Some(5),
                &MachineFilter {
                    status: Some(MachineStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .expect("list");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].hostname, "host-a");

        let offline = svc
            .list(
                at(15),
                Some(5),
                &MachineFilter {
                    liveness: Some(LivenessStatus::Offline),
                    ..Default::default()
                },
            )
            .await
            .expect("list");
        assert_eq!(offline.len(), 1);
        assert_eq!(offline[0].hostname, "host-b");
    }

    #[tokio::test]
    async fn set_status_and_delete() {
        let svc = seeded().await;
        let updated = svc
            .set_status("srv_b", MachineStatus::Active, at(20))
            .await
            .expect("enable");
        assert_eq!(updated.status, MachineStatus::Active);

        let deleted = svc.delete("srv_a").await.expect("delete");
        assert_eq!(deleted.hostname, "host-a");
        assert!(svc.find("srv_a").await.expect("find").is_none());

        let missing = svc.set_status("nope", MachineStatus::Active, at(20)).await;
        assert!(matches!(missing, Err(MachineAdminError::NotFound(_))));
    }
}
