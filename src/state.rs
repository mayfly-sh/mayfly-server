//! Shared application state.
//!
//! [`AppState`] is the dependency container handed to every HTTP handler. It
//! is cheap to clone (all fields are `Arc`-shared or themselves clonable
//! handles) so Axum can clone it per request.

use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use sqlx::SqlitePool;

use crate::clock::Clock;
use crate::config::Config;

/// Application-wide shared state.
#[derive(Clone)]
pub struct AppState {
    /// Immutable, validated configuration.
    config: Arc<Config>,
    /// Database connection pool (clones share the same pool).
    db: SqlitePool,
    /// Time source; never call `Utc::now()` directly in handlers.
    clock: Arc<dyn Clock>,
    /// When the process finished initializing, per `clock`.
    started_at: DateTime<Utc>,
}

impl AppState {
    /// Construct application state, capturing the startup timestamp from the
    /// provided clock so it is consistent with all other time reads.
    pub fn new(config: Config, db: SqlitePool, clock: Arc<dyn Clock>) -> Self {
        let started_at = clock.now();
        Self {
            config: Arc::new(config),
            db,
            clock,
            started_at,
        }
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Borrow the database pool.
    pub fn db(&self) -> &SqlitePool {
        &self.db
    }

    /// Borrow the clock for reading the current time.
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Clone the shared clock handle, e.g. to move into a spawned task.
    pub fn clock_arc(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// The instant the application started.
    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Elapsed time since startup, measured by the application clock.
    ///
    /// Clamped to be non-negative: the underlying [`Clock`] is wall-clock based
    /// and may step backwards (NTP), which must never yield negative uptime.
    pub fn uptime(&self) -> TimeDelta {
        (self.clock.now() - self.started_at).max(TimeDelta::zero())
    }
}

impl std::fmt::Debug for AppState {
    /// Redacted debug output: never prints the full config (future secrets),
    /// the database handle, or the clock.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("server_host", &self.config.server.host)
            .field("server_port", &self.config.server.port)
            .field("started_at", &self.started_at)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::config::Config;
    use crate::db;

    async fn test_state(clock: Arc<dyn Clock>) -> AppState {
        let pool = db::connect(":memory:").await.expect("connect");
        let mut config = Config::default();
        config.server.tls.enabled = false;
        AppState::new(config, pool, clock)
    }

    #[tokio::test]
    async fn captures_startup_timestamp_from_clock() {
        let clock = Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap());
        let state = test_state(clock).await;
        assert_eq!(
            state.started_at().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2026-06-24T12:00:00Z"
        );
    }

    #[tokio::test]
    async fn uptime_tracks_clock_advancement() {
        let test_clock = Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap());
        let state = test_state(test_clock.clone() as Arc<dyn Clock>).await;

        assert_eq!(state.uptime(), TimeDelta::zero());
        test_clock.advance(TimeDelta::seconds(42));
        assert_eq!(state.uptime(), TimeDelta::seconds(42));
    }

    #[tokio::test]
    async fn is_cloneable_and_shares_pool() {
        let clock = Arc::new(SystemClockForTest);
        let state = test_state(clock).await;
        let cloned = state.clone();
        // Both clones reference a working pool.
        assert!(sqlx::query("SELECT 1").execute(state.db()).await.is_ok());
        assert!(sqlx::query("SELECT 1").execute(cloned.db()).await.is_ok());
    }

    #[test]
    fn app_state_is_send_sync_clone() {
        fn assert_bounds<T: Send + Sync + Clone + 'static>() {}
        assert_bounds::<AppState>();
    }

    #[tokio::test]
    async fn uptime_is_clamped_when_clock_steps_backward() {
        let clock = Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap());
        let state = test_state(clock.clone() as Arc<dyn Clock>).await;
        clock.set(
            chrono::DateTime::parse_from_rfc3339("2026-06-24T11:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert_eq!(state.uptime(), TimeDelta::zero());
    }

    #[tokio::test]
    async fn debug_is_redacted() {
        let clock = Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap());
        let state = test_state(clock).await;
        let rendered = format!("{state:?}");
        assert!(rendered.contains("AppState"));
        assert!(rendered.contains("server_port"));
        // Database URL must not appear in debug output.
        assert!(!rendered.contains("memory"));
    }

    #[derive(Debug)]
    struct SystemClockForTest;
    impl Clock for SystemClockForTest {
        fn now(&self) -> DateTime<Utc> {
            Utc::now()
        }
    }
}
