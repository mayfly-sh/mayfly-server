//! Polling-interval jitter.
//!
//! Without jitter every agent that enrolled at the same time polls in lockstep,
//! producing synchronized thundering-herd load on the server (and on `sshd`
//! reloads across the fleet). We spread polls by adding a uniformly random
//! offset within `±jitter_percent` of the configured interval.
//!
//! Randomness is dependency-injected via the existing [`RandomSource`] (the
//! same CSPRNG abstraction used for CA selection), so tests are fully
//! deterministic and production uses the OS CSPRNG — never `thread_rng`.

use crate::ca::RandomSource;

/// Compute a jittered interval: `base ± (base * percent / 100)`, drawn
/// uniformly over the inclusive integer range, using the injected CSPRNG.
///
/// - `percent` is clamped to `0..=100`.
/// - The result is clamped to a minimum of 1 second (an interval of 0 would
///   busy-loop a poller).
///
/// Example: `with_jitter(60, 10, rng)` returns a value in `54..=66`.
pub fn with_jitter(base_seconds: u32, percent: u8, rng: &dyn RandomSource) -> u32 {
    let percent = u32::from(percent.min(100));
    if base_seconds == 0 {
        return 1;
    }
    // Largest offset magnitude in seconds.
    let delta = base_seconds.saturating_mul(percent) / 100;
    if delta == 0 {
        return base_seconds.max(1);
    }

    // Choose an offset uniformly in [-delta, +delta] via an index in
    // [0, 2*delta] (inclusive), i.e. a span of 2*delta + 1 values.
    let span = (delta as usize) * 2 + 1;
    let offset = rng.next_index(span) as i64 - delta as i64;

    let jittered = base_seconds as i64 + offset;
    jittered.max(1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::Arc;

    /// Deterministic RNG returning a fixed index (clamped to bound).
    struct FixedRng(usize);
    impl RandomSource for FixedRng {
        fn next_index(&self, bound: usize) -> usize {
            self.0 % bound
        }
    }

    /// RNG cycling through a sequence, mirroring the manager's test RNG.
    struct SeqRng {
        seq: Vec<usize>,
        cursor: Mutex<usize>,
    }
    impl RandomSource for SeqRng {
        fn next_index(&self, bound: usize) -> usize {
            let mut c = self.cursor.lock().unwrap();
            let v = self.seq[*c % self.seq.len()] % bound;
            *c += 1;
            v
        }
    }

    #[test]
    fn lowest_index_is_lower_bound() {
        // index 0 -> offset = -delta -> 60 - 6 = 54
        assert_eq!(with_jitter(60, 10, &FixedRng(0)), 54);
    }

    #[test]
    fn highest_index_is_upper_bound() {
        // span = 13, top index 12 -> offset = +6 -> 66
        assert_eq!(with_jitter(60, 10, &FixedRng(12)), 66);
    }

    #[test]
    fn midpoint_index_is_base() {
        // index 6 -> offset 0 -> 60
        assert_eq!(with_jitter(60, 10, &FixedRng(6)), 60);
    }

    #[test]
    fn zero_percent_returns_base() {
        assert_eq!(with_jitter(60, 0, &FixedRng(0)), 60);
    }

    #[test]
    fn result_never_below_one() {
        // Tiny base, full jitter: still at least 1.
        assert_eq!(with_jitter(1, 100, &FixedRng(0)), 1);
    }

    #[test]
    fn all_results_stay_within_bounds() {
        let rng = Arc::new(SeqRng {
            seq: (0..1000).collect(),
            cursor: Mutex::new(0),
        });
        for _ in 0..1000 {
            let v = with_jitter(300, 20, rng.as_ref());
            assert!((240..=360).contains(&v), "out of range: {v}");
        }
    }

    proptest::proptest! {
        #[test]
        fn jitter_within_declared_window(
            base in 1u32..=86_400,
            percent in 0u8..=100,
            idx in 0usize..100_000,
        ) {
            let v = with_jitter(base, percent, &FixedRng(idx));
            let delta = base.saturating_mul(u32::from(percent)) / 100;
            let lo = base.saturating_sub(delta).max(1);
            let hi = base.saturating_add(delta);
            proptest::prop_assert!(v >= lo && v <= hi, "v={v} lo={lo} hi={hi}");
        }
    }
}
