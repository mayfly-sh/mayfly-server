//! Replay protection via a per-request nonce cache.
//!
//! A signed request is accepted at most once inside the timestamp window. The
//! [`NonceCache`] trait records `(machine_id, nonce)` pairs with a TTL; a repeat
//! within the TTL is a replay and is rejected. The cache is keyed by machine so
//! two different machines may independently pick the same nonce.
//!
//! [`InMemoryNonceCache`] is the default, dependency-free implementation. The
//! trait exists so a shared store (e.g. Redis) can replace it once the server
//! runs as more than one process — no caller changes required.
//!
//! Time is always supplied by the caller (from the injected clock); the cache
//! never reads the wall clock itself, keeping expiry fully deterministic in
//! tests.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, TimeDelta, Utc};

/// How long a nonce is remembered. Must comfortably exceed the timestamp skew
/// window so a replay can never outlive the cache entry that blocks it.
pub const NONCE_TTL_SECS: i64 = 120;

/// Records recently-seen request nonces to reject replays.
pub trait NonceCache: Send + Sync + std::fmt::Debug {
    /// Atomically check-and-record `(machine_id, nonce)` as of `now`.
    ///
    /// Returns `true` if the nonce was newly recorded (the request may
    /// proceed), or `false` if it was already present within the TTL (a replay
    /// that must be rejected).
    fn check_and_record(&self, machine_id: &str, nonce: &str, now: DateTime<Utc>) -> bool;
}

/// Process-local nonce cache backed by a `HashMap` of expiry instants.
#[derive(Debug, Default)]
pub struct InMemoryNonceCache {
    /// Maps `(machine_id, nonce)` to the instant the entry expires.
    entries: Mutex<HashMap<(String, String), DateTime<Utc>>>,
}

impl InMemoryNonceCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live (not-yet-purged) entries. Exposed for tests/metrics.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), DateTime<Utc>>> {
        // The protected map is always internally consistent, so on a poisoned
        // lock we recover the inner value rather than propagating a panic.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl NonceCache for InMemoryNonceCache {
    fn check_and_record(&self, machine_id: &str, nonce: &str, now: DateTime<Utc>) -> bool {
        let expiry = now + TimeDelta::seconds(NONCE_TTL_SECS);
        let mut map = self.lock();

        // Opportunistically drop expired entries so the map cannot grow without
        // bound; an entry is live only while its expiry is strictly in the past.
        map.retain(|_, exp| *exp > now);

        let key = (machine_id.to_string(), nonce.to_string());
        match map.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(expiry);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(unix, 0).expect("valid timestamp")
    }

    #[test]
    fn first_use_is_accepted_replay_is_rejected() {
        let cache = InMemoryNonceCache::new();
        assert!(cache.check_and_record("m1", "n1", at(1000)));
        // Same machine + nonce within TTL => replay.
        assert!(!cache.check_and_record("m1", "n1", at(1001)));
    }

    #[test]
    fn different_machines_may_share_a_nonce() {
        let cache = InMemoryNonceCache::new();
        assert!(cache.check_and_record("m1", "shared", at(1000)));
        assert!(cache.check_and_record("m2", "shared", at(1000)));
    }

    #[test]
    fn distinct_nonces_for_one_machine_are_accepted() {
        let cache = InMemoryNonceCache::new();
        assert!(cache.check_and_record("m1", "n1", at(1000)));
        assert!(cache.check_and_record("m1", "n2", at(1000)));
    }

    #[test]
    fn nonce_is_reusable_after_ttl_expires() {
        let cache = InMemoryNonceCache::new();
        assert!(cache.check_and_record("m1", "n1", at(1000)));
        // Just before expiry: still a replay (well beyond the 60s timestamp
        // window, so this boundary never affects real replay protection).
        assert!(!cache.check_and_record("m1", "n1", at(1000 + NONCE_TTL_SECS - 1)));
        // At expiry the entry is purged and the nonce is fresh again.
        assert!(cache.check_and_record("m1", "n1", at(1000 + NONCE_TTL_SECS)));
    }

    #[test]
    fn expired_entries_are_purged() {
        let cache = InMemoryNonceCache::new();
        cache.check_and_record("m1", "n1", at(1000));
        assert_eq!(cache.len(), 1);
        // A later, unrelated insert triggers the purge of the expired entry.
        cache.check_and_record("m2", "n2", at(2000));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
    }
}
