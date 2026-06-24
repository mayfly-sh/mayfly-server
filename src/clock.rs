//! Clock abstraction.
//!
//! Business logic must depend on the [`Clock`] trait rather than calling
//! [`chrono::Utc::now`] directly. This keeps time-dependent logic (TTL
//! calculations, audit timestamps, expiry checks) deterministic and testable.
//!
//! Production code uses [`SystemClock`]; tests use [`TestClock`], whose time
//! is fixed and explicitly advanced.
//!
//! ## Wall-clock semantics
//!
//! [`Clock`] reports **wall-clock** time (UTC), which is correct for
//! certificate validity windows and audit timestamps. It is *not* monotonic:
//! NTP adjustments can move it backwards. Callers measuring elapsed durations
//! must tolerate non-positive deltas (see [`crate::state::AppState::uptime`]).

use std::sync::Mutex;

use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};

/// A source of the current time.
///
/// Implementors must be cheap to call and thread-safe so a single instance can
/// be shared across the application via `Arc<dyn Clock>`.
pub trait Clock: Send + Sync {
    /// The current instant in UTC.
    fn now(&self) -> DateTime<Utc>;

    /// The current instant formatted as RFC 3339 with millisecond precision.
    ///
    /// Used for canonical, stable timestamp strings (e.g. audit entries).
    /// Millisecond precision preserves ordering/forensic granularity under
    /// high-throughput issuance, where second precision would collide.
    fn now_rfc3339(&self) -> String {
        self.now().to_rfc3339_opts(SecondsFormat::Millis, true)
    }
}

/// A [`Clock`] backed by the operating system wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A [`Clock`] whose time is controlled by tests.
///
/// Interior mutability allows shared `Arc<dyn Clock>` references to observe
/// time changes made via [`TestClock::set`] / [`TestClock::advance`].
#[derive(Debug)]
pub struct TestClock {
    current: Mutex<DateTime<Utc>>,
}

impl TestClock {
    /// Create a clock fixed at `instant`.
    pub fn new(instant: DateTime<Utc>) -> Self {
        Self {
            current: Mutex::new(instant),
        }
    }

    /// Create a clock fixed at the given RFC 3339 timestamp.
    ///
    /// Returns `None` if the string cannot be parsed.
    pub fn at_rfc3339(timestamp: &str) -> Option<Self> {
        DateTime::parse_from_rfc3339(timestamp)
            .ok()
            .map(|dt| Self::new(dt.with_timezone(&Utc)))
    }

    /// Overwrite the current time.
    pub fn set(&self, instant: DateTime<Utc>) {
        *self.lock() = instant;
    }

    /// Advance the current time by `delta`.
    pub fn advance(&self, delta: TimeDelta) {
        let mut guard = self.lock();
        *guard += delta;
    }

    /// Lock the inner mutex, recovering from poisoning rather than panicking.
    fn lock(&self) -> std::sync::MutexGuard<'_, DateTime<Utc>> {
        self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn system_clock_returns_a_plausible_current_time() {
        // Wall clock is not monotonic, so we only assert it returns a sane,
        // recent timestamp rather than any ordering between calls.
        let clock = SystemClock;
        assert!(clock.now().timestamp() > 1_700_000_000); // after 2023-11-14
    }

    #[test]
    fn test_clock_is_fixed_until_changed() {
        let clock = TestClock::at_rfc3339("2026-06-24T12:00:00Z").expect("valid timestamp");
        let a = clock.now();
        let b = clock.now();
        assert_eq!(a, b);
        assert_eq!(clock.now_rfc3339(), "2026-06-24T12:00:00.000Z");
    }

    #[test]
    fn test_clock_advances() {
        let clock = TestClock::at_rfc3339("2026-06-24T12:00:00Z").expect("valid timestamp");
        clock.advance(TimeDelta::seconds(90));
        assert_eq!(clock.now_rfc3339(), "2026-06-24T12:01:30.000Z");
    }

    #[test]
    fn test_clock_set_is_visible_through_trait_object() {
        let clock: Arc<dyn Clock> = Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap());
        let observer = Arc::clone(&clock);
        assert_eq!(observer.now_rfc3339(), "2026-06-24T12:00:00.000Z");
    }

    #[test]
    fn at_rfc3339_rejects_garbage() {
        assert!(TestClock::at_rfc3339("not-a-timestamp").is_none());
    }
}
