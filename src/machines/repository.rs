//! Persistence for machines and enrollment tokens.
//!
//! Traits come first ([`MachineRepository`], [`EnrollmentTokenRepository`]) so
//! the service depends on abstractions; the SQLite implementations follow. All
//! mutating methods take a `&mut SqliteConnection` rather than a pool so the
//! service can run the whole enrollment (token lookup → dup checks → consume →
//! insert) inside a **single transaction**: the caller passes `&mut *tx`.
//!
//! There are deliberately no update/delete methods beyond the single-use token
//! consume; this module is the only write path to either table.

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::SqliteConnection;

use crate::machines::models::{
    EnrollmentToken, Machine, MachineStatus, NewEnrollmentToken, NewMachine,
};

/// Render a timestamp the way it is stored (RFC 3339, millisecond precision).
fn to_text(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse a stored timestamp back into a `DateTime<Utc>`.
fn parse_dt(value: &str) -> Result<DateTime<Utc>, sqlx::Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| sqlx::Error::Decode(format!("invalid stored timestamp: {err}").into()))
}

/// Read/write access to enrolled machines.
#[async_trait]
pub trait MachineRepository: Send + Sync {
    /// Find a machine by its hostname.
    async fn find_by_hostname(
        &self,
        conn: &mut SqliteConnection,
        hostname: &str,
    ) -> Result<Option<Machine>, sqlx::Error>;

    /// Find a machine by its public key.
    async fn find_by_public_key(
        &self,
        conn: &mut SqliteConnection,
        public_key: &str,
    ) -> Result<Option<Machine>, sqlx::Error>;

    /// Find a machine by its server-issued identifier.
    async fn find_by_id(
        &self,
        conn: &mut SqliteConnection,
        machine_id: &str,
    ) -> Result<Option<Machine>, sqlx::Error>;

    /// Insert a new machine, returning the persisted row.
    ///
    /// Relies on the table's `UNIQUE` constraints on `hostname` and
    /// `public_key` as the final word on duplicates, so a race between a
    /// pre-check and the insert still fails closed.
    async fn insert(
        &self,
        conn: &mut SqliteConnection,
        new: &NewMachine,
    ) -> Result<Machine, sqlx::Error>;

    /// Record a heartbeat: stamp `last_seen = now` and refresh the
    /// agent-reported `agent_version`, `ip`, and `current_generation`.
    ///
    /// Returns `true` if a row was updated, `false` if no machine matched.
    /// Never alters lifecycle `status`: liveness is derived, not stored.
    async fn update_last_seen(
        &self,
        conn: &mut SqliteConnection,
        update: &HeartbeatUpdate<'_>,
    ) -> Result<bool, sqlx::Error>;

    /// List the most recently active machines, newest `last_seen` first
    /// (never-seen machines sort last), capped at `limit` rows.
    async fn list_recent(
        &self,
        conn: &mut SqliteConnection,
        limit: i64,
    ) -> Result<Vec<Machine>, sqlx::Error>;
}

/// The mutable fields a heartbeat refreshes on a machine row.
#[derive(Debug, Clone)]
pub struct HeartbeatUpdate<'a> {
    /// Identifier of the machine being updated.
    pub machine_id: &'a str,
    /// Heartbeat receipt time, stored as `last_seen`/`updated_at`.
    pub now: DateTime<Utc>,
    /// Agent version reported in this heartbeat.
    pub agent_version: &'a str,
    /// Self-reported IP address, if any.
    pub ip: Option<&'a str>,
    /// Self-reported configuration generation.
    pub current_generation: i64,
}

/// Read/write access to enrollment tokens.
#[async_trait]
pub trait EnrollmentTokenRepository: Send + Sync {
    /// Persist a new enrollment token (hash only) and return its record.
    async fn create(
        &self,
        conn: &mut SqliteConnection,
        new: &NewEnrollmentToken,
    ) -> Result<EnrollmentToken, sqlx::Error>;

    /// Find a token by its SHA-256 hash.
    async fn find_by_hash(
        &self,
        conn: &mut SqliteConnection,
        token_hash: &str,
    ) -> Result<Option<EnrollmentToken>, sqlx::Error>;

    /// Atomically consume a token, stamping `used_at = now`.
    ///
    /// For a single-use token the update is conditional on `used_at IS NULL`,
    /// so concurrent enrollments race on this `UPDATE` and exactly one wins.
    /// Returns `true` if this call consumed the token, `false` if it was
    /// already consumed (single-use only).
    async fn consume(
        &self,
        conn: &mut SqliteConnection,
        token_id: &str,
        single_use: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error>;
}

/// SQLite-backed [`MachineRepository`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteMachineRepository;

/// SQLite-backed [`EnrollmentTokenRepository`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteEnrollmentTokenRepository;

#[derive(sqlx::FromRow)]
struct MachineRow {
    machine_id: String,
    hostname: String,
    public_key: String,
    os: String,
    arch: String,
    agent_version: String,
    status: String,
    ip: Option<String>,
    current_generation: i64,
    last_seen: Option<String>,
    enrolled_at: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<MachineRow> for Machine {
    type Error = sqlx::Error;

    fn try_from(row: MachineRow) -> Result<Self, Self::Error> {
        let status = MachineStatus::from_db_str(&row.status).ok_or_else(|| {
            sqlx::Error::Decode(format!("unknown machine status '{}'", row.status).into())
        })?;
        let last_seen = row.last_seen.as_deref().map(parse_dt).transpose()?;
        Ok(Machine {
            machine_id: row.machine_id,
            hostname: row.hostname,
            public_key: row.public_key,
            os: row.os,
            arch: row.arch,
            agent_version: row.agent_version,
            status,
            ip: row.ip,
            current_generation: row.current_generation,
            last_seen,
            enrolled_at: parse_dt(&row.enrolled_at)?,
            created_at: parse_dt(&row.created_at)?,
            updated_at: parse_dt(&row.updated_at)?,
        })
    }
}

const MACHINE_COLUMNS: &str = "machine_id, hostname, public_key, os, arch, agent_version, \
     status, ip, current_generation, last_seen, enrolled_at, created_at, updated_at";

#[async_trait]
impl MachineRepository for SqliteMachineRepository {
    async fn find_by_hostname(
        &self,
        conn: &mut SqliteConnection,
        hostname: &str,
    ) -> Result<Option<Machine>, sqlx::Error> {
        let row = sqlx::query_as::<_, MachineRow>(&format!(
            "SELECT {MACHINE_COLUMNS} FROM machines WHERE hostname = ?"
        ))
        .bind(hostname)
        .fetch_optional(&mut *conn)
        .await?;
        row.map(Machine::try_from).transpose()
    }

    async fn find_by_public_key(
        &self,
        conn: &mut SqliteConnection,
        public_key: &str,
    ) -> Result<Option<Machine>, sqlx::Error> {
        let row = sqlx::query_as::<_, MachineRow>(&format!(
            "SELECT {MACHINE_COLUMNS} FROM machines WHERE public_key = ?"
        ))
        .bind(public_key)
        .fetch_optional(&mut *conn)
        .await?;
        row.map(Machine::try_from).transpose()
    }

    async fn find_by_id(
        &self,
        conn: &mut SqliteConnection,
        machine_id: &str,
    ) -> Result<Option<Machine>, sqlx::Error> {
        let row = sqlx::query_as::<_, MachineRow>(&format!(
            "SELECT {MACHINE_COLUMNS} FROM machines WHERE machine_id = ?"
        ))
        .bind(machine_id)
        .fetch_optional(&mut *conn)
        .await?;
        row.map(Machine::try_from).transpose()
    }

    async fn insert(
        &self,
        conn: &mut SqliteConnection,
        new: &NewMachine,
    ) -> Result<Machine, sqlx::Error> {
        let enrolled_at = to_text(new.enrolled_at);
        // `current_generation` defaults to 0 and `ip`/`last_seen` to NULL until
        // the first heartbeat arrives.
        sqlx::query(
            "INSERT INTO machines (\
                machine_id, hostname, public_key, os, arch, agent_version, \
                status, ip, current_generation, last_seen, enrolled_at, created_at, updated_at\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, NULL, ?, ?, ?)",
        )
        .bind(&new.machine_id)
        .bind(&new.hostname)
        .bind(&new.public_key)
        .bind(&new.os)
        .bind(&new.arch)
        .bind(&new.agent_version)
        .bind(new.status.as_str())
        .bind(&enrolled_at)
        .bind(&enrolled_at)
        .bind(&enrolled_at)
        .execute(&mut *conn)
        .await?;

        Ok(Machine {
            machine_id: new.machine_id.clone(),
            hostname: new.hostname.clone(),
            public_key: new.public_key.clone(),
            os: new.os.clone(),
            arch: new.arch.clone(),
            agent_version: new.agent_version.clone(),
            status: new.status,
            ip: None,
            current_generation: 0,
            last_seen: None,
            enrolled_at: new.enrolled_at,
            created_at: new.enrolled_at,
            updated_at: new.enrolled_at,
        })
    }

    async fn update_last_seen(
        &self,
        conn: &mut SqliteConnection,
        update: &HeartbeatUpdate<'_>,
    ) -> Result<bool, sqlx::Error> {
        let now_text = to_text(update.now);
        let result = sqlx::query(
            "UPDATE machines \
             SET last_seen = ?, updated_at = ?, agent_version = ?, ip = ?, current_generation = ? \
             WHERE machine_id = ?",
        )
        .bind(&now_text)
        .bind(&now_text)
        .bind(update.agent_version)
        .bind(update.ip)
        .bind(update.current_generation)
        .bind(update.machine_id)
        .execute(&mut *conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_recent(
        &self,
        conn: &mut SqliteConnection,
        limit: i64,
    ) -> Result<Vec<Machine>, sqlx::Error> {
        let rows = sqlx::query_as::<_, MachineRow>(&format!(
            "SELECT {MACHINE_COLUMNS} FROM machines \
             ORDER BY last_seen DESC NULLS LAST, created_at DESC LIMIT ?"
        ))
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter().map(Machine::try_from).collect()
    }
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: String,
    token_hash: String,
    created_at: String,
    expires_at: String,
    used_at: Option<String>,
    created_by: String,
    single_use: i64,
}

impl TryFrom<TokenRow> for EnrollmentToken {
    type Error = sqlx::Error;

    fn try_from(row: TokenRow) -> Result<Self, Self::Error> {
        let used_at = row.used_at.as_deref().map(parse_dt).transpose()?;
        Ok(EnrollmentToken {
            id: row.id,
            token_hash: row.token_hash,
            created_at: parse_dt(&row.created_at)?,
            expires_at: parse_dt(&row.expires_at)?,
            used_at,
            created_by: row.created_by,
            single_use: row.single_use != 0,
        })
    }
}

const TOKEN_COLUMNS: &str =
    "id, token_hash, created_at, expires_at, used_at, created_by, single_use";

#[async_trait]
impl EnrollmentTokenRepository for SqliteEnrollmentTokenRepository {
    async fn create(
        &self,
        conn: &mut SqliteConnection,
        new: &NewEnrollmentToken,
    ) -> Result<EnrollmentToken, sqlx::Error> {
        sqlx::query(
            "INSERT INTO machine_enrollment_tokens (\
                id, token_hash, created_at, expires_at, used_at, created_by, single_use\
             ) VALUES (?, ?, ?, ?, NULL, ?, ?)",
        )
        .bind(&new.id)
        .bind(&new.token_hash)
        .bind(to_text(new.created_at))
        .bind(to_text(new.expires_at))
        .bind(&new.created_by)
        .bind(i64::from(new.single_use))
        .execute(&mut *conn)
        .await?;

        Ok(EnrollmentToken {
            id: new.id.clone(),
            token_hash: new.token_hash.clone(),
            created_at: new.created_at,
            expires_at: new.expires_at,
            used_at: None,
            created_by: new.created_by.clone(),
            single_use: new.single_use,
        })
    }

    async fn find_by_hash(
        &self,
        conn: &mut SqliteConnection,
        token_hash: &str,
    ) -> Result<Option<EnrollmentToken>, sqlx::Error> {
        let row = sqlx::query_as::<_, TokenRow>(&format!(
            "SELECT {TOKEN_COLUMNS} FROM machine_enrollment_tokens WHERE token_hash = ?"
        ))
        .bind(token_hash)
        .fetch_optional(&mut *conn)
        .await?;
        row.map(EnrollmentToken::try_from).transpose()
    }

    async fn consume(
        &self,
        conn: &mut SqliteConnection,
        token_id: &str,
        single_use: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let now_text = to_text(now);
        let result = if single_use {
            // Conditional update: only the first concurrent consumer succeeds.
            sqlx::query(
                "UPDATE machine_enrollment_tokens SET used_at = ? \
                 WHERE id = ? AND used_at IS NULL",
            )
            .bind(&now_text)
            .bind(token_id)
            .execute(&mut *conn)
            .await?
        } else {
            // Reusable token: record the most recent use without blocking.
            sqlx::query("UPDATE machine_enrollment_tokens SET used_at = ? WHERE id = ?")
                .bind(&now_text)
                .bind(token_id)
                .execute(&mut *conn)
                .await?
        };
        Ok(result.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use chrono::{TimeDelta, TimeZone};
    use sqlx::Connection;

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

    fn new_token(id: &str, hash: &str, single_use: bool) -> NewEnrollmentToken {
        NewEnrollmentToken {
            id: id.to_string(),
            token_hash: hash.to_string(),
            created_at: at(0),
            expires_at: at(0) + TimeDelta::hours(1),
            created_by: "admin".to_string(),
            single_use,
        }
    }

    async fn conn() -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
        let pool = db::connect(":memory:").await.expect("connect");
        // Keep one persistent connection so the in-memory DB survives the test.
        pool.acquire().await.expect("acquire")
    }

    #[tokio::test]
    async fn machine_insert_and_lookup_round_trip() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        let inserted = repo
            .insert(&mut c, &new_machine("01", MachineStatus::Active))
            .await
            .expect("insert");

        let by_id = repo
            .find_by_id(&mut c, &inserted.machine_id)
            .await
            .expect("find")
            .expect("present");
        assert_eq!(by_id, inserted);
        assert_eq!(by_id.status, MachineStatus::Active);

        let by_host = repo
            .find_by_hostname(&mut c, &inserted.hostname)
            .await
            .expect("find")
            .expect("present");
        assert_eq!(by_host, inserted);

        let by_key = repo
            .find_by_public_key(&mut c, &inserted.public_key)
            .await
            .expect("find")
            .expect("present");
        assert_eq!(by_key, inserted);
    }

    #[tokio::test]
    async fn update_last_seen_refreshes_heartbeat_fields() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        repo.insert(&mut c, &new_machine("01", MachineStatus::Active))
            .await
            .expect("insert");

        let update = HeartbeatUpdate {
            machine_id: "srv_01",
            now: at(30),
            agent_version: "0.2.0",
            ip: Some("10.0.0.5"),
            current_generation: 42,
        };
        assert!(repo
            .update_last_seen(&mut c, &update)
            .await
            .expect("update"));

        let machine = repo
            .find_by_id(&mut c, "srv_01")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(machine.last_seen, Some(at(30)));
        assert_eq!(machine.agent_version, "0.2.0");
        assert_eq!(machine.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(machine.current_generation, 42);
        // Lifecycle status is never touched by a heartbeat.
        assert_eq!(machine.status, MachineStatus::Active);
    }

    #[tokio::test]
    async fn update_last_seen_unknown_machine_returns_false() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        let update = HeartbeatUpdate {
            machine_id: "srv_missing",
            now: at(30),
            agent_version: "0.2.0",
            ip: None,
            current_generation: 1,
        };
        assert!(!repo
            .update_last_seen(&mut c, &update)
            .await
            .expect("update"));
    }

    #[tokio::test]
    async fn list_recent_orders_by_last_seen_desc_nulls_last() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        for s in ["a", "b", "c"] {
            repo.insert(&mut c, &new_machine(s, MachineStatus::Active))
                .await
                .expect("insert");
        }
        // b seen later than a; c never seen.
        repo.update_last_seen(
            &mut c,
            &HeartbeatUpdate {
                machine_id: "srv_a",
                now: at(10),
                agent_version: "0.1.0",
                ip: None,
                current_generation: 0,
            },
        )
        .await
        .expect("update a");
        repo.update_last_seen(
            &mut c,
            &HeartbeatUpdate {
                machine_id: "srv_b",
                now: at(20),
                agent_version: "0.1.0",
                ip: None,
                current_generation: 0,
            },
        )
        .await
        .expect("update b");

        let listed = repo.list_recent(&mut c, 10).await.expect("list");
        let ids: Vec<&str> = listed.iter().map(|m| m.machine_id.as_str()).collect();
        assert_eq!(ids, vec!["srv_b", "srv_a", "srv_c"]);
    }

    #[tokio::test]
    async fn list_recent_respects_limit() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        for s in ["a", "b", "c"] {
            repo.insert(&mut c, &new_machine(s, MachineStatus::Active))
                .await
                .expect("insert");
        }
        assert_eq!(repo.list_recent(&mut c, 2).await.expect("list").len(), 2);
    }

    #[tokio::test]
    async fn machine_lookup_misses_return_none() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        assert!(repo.find_by_id(&mut c, "nope").await.expect("q").is_none());
        assert!(repo
            .find_by_hostname(&mut c, "nope")
            .await
            .expect("q")
            .is_none());
        assert!(repo
            .find_by_public_key(&mut c, "nope")
            .await
            .expect("q")
            .is_none());
    }

    #[tokio::test]
    async fn duplicate_hostname_violates_unique_constraint() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        repo.insert(&mut c, &new_machine("01", MachineStatus::Active))
            .await
            .expect("first");

        let mut dup = new_machine("02", MachineStatus::Active);
        dup.hostname = "host-01".to_string();
        let err = repo.insert(&mut c, &dup).await.expect_err("dup hostname");
        assert!(matches!(err, sqlx::Error::Database(_)));
    }

    #[tokio::test]
    async fn duplicate_public_key_violates_unique_constraint() {
        let mut c = conn().await;
        let repo = SqliteMachineRepository;
        repo.insert(&mut c, &new_machine("01", MachineStatus::Active))
            .await
            .expect("first");

        let mut dup = new_machine("02", MachineStatus::Active);
        dup.public_key = "ssh-ed25519 AAAA01".to_string();
        let err = repo.insert(&mut c, &dup).await.expect_err("dup key");
        assert!(matches!(err, sqlx::Error::Database(_)));
    }

    #[tokio::test]
    async fn token_create_find_and_consume() {
        let mut c = conn().await;
        let repo = SqliteEnrollmentTokenRepository;
        let created = repo
            .create(&mut c, &new_token("tok1", "hash-abc", true))
            .await
            .expect("create");
        assert!(created.used_at.is_none());
        assert!(created.single_use);

        let found = repo
            .find_by_hash(&mut c, "hash-abc")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(found, created);

        // First consume succeeds, second fails (single-use).
        assert!(repo
            .consume(&mut c, "tok1", true, at(5))
            .await
            .expect("consume"));
        assert!(!repo
            .consume(&mut c, "tok1", true, at(6))
            .await
            .expect("re-consume"));

        let after = repo
            .find_by_hash(&mut c, "hash-abc")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(after.used_at, Some(at(5)));
    }

    #[tokio::test]
    async fn reusable_token_can_be_consumed_repeatedly() {
        let mut c = conn().await;
        let repo = SqliteEnrollmentTokenRepository;
        repo.create(&mut c, &new_token("tok2", "hash-reuse", false))
            .await
            .expect("create");
        assert!(repo
            .consume(&mut c, "tok2", false, at(5))
            .await
            .expect("consume"));
        assert!(repo
            .consume(&mut c, "tok2", false, at(6))
            .await
            .expect("consume again"));
    }

    #[tokio::test]
    async fn find_missing_token_returns_none() {
        let mut c = conn().await;
        let repo = SqliteEnrollmentTokenRepository;
        assert!(repo
            .find_by_hash(&mut c, "absent")
            .await
            .expect("q")
            .is_none());
    }

    #[tokio::test]
    async fn insert_and_consume_within_a_transaction_commit() {
        let pool = db::connect(":memory:").await.expect("connect");
        let mut held = pool.acquire().await.expect("hold");
        let machines = SqliteMachineRepository;
        let tokens = SqliteEnrollmentTokenRepository;

        let mut tx = held.begin().await.expect("begin");
        tokens
            .create(&mut tx, &new_token("tok3", "hash-tx", true))
            .await
            .expect("create");
        assert!(tokens
            .consume(&mut tx, "tok3", true, at(1))
            .await
            .expect("consume"));
        machines
            .insert(&mut tx, &new_machine("tx", MachineStatus::Active))
            .await
            .expect("insert");
        tx.commit().await.expect("commit");

        assert!(machines
            .find_by_id(&mut held, "srv_tx")
            .await
            .expect("q")
            .is_some());
    }

    #[tokio::test]
    async fn transaction_rollback_discards_all_writes() {
        let pool = db::connect(":memory:").await.expect("connect");
        let mut held = pool.acquire().await.expect("hold");
        let machines = SqliteMachineRepository;
        let tokens = SqliteEnrollmentTokenRepository;
        tokens
            .create(&mut held, &new_token("tok4", "hash-rb", true))
            .await
            .expect("seed token");

        let mut tx = held.begin().await.expect("begin");
        tokens
            .consume(&mut tx, "tok4", true, at(1))
            .await
            .expect("consume");
        machines
            .insert(&mut tx, &new_machine("rb", MachineStatus::Active))
            .await
            .expect("insert");
        // Drop without commit => rollback.
        drop(tx);

        // Machine never persisted; token never consumed.
        assert!(machines
            .find_by_id(&mut held, "srv_rb")
            .await
            .expect("q")
            .is_none());
        let token = tokens
            .find_by_hash(&mut held, "hash-rb")
            .await
            .expect("q")
            .expect("present");
        assert!(token.used_at.is_none());
    }
}
