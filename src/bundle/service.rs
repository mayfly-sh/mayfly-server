//! The bundle distribution service: building/signing the [`SignedBundle`],
//! recording agent acknowledgements, fleet rollout metrics, and CA retirement
//! safety assessment.
//!
//! This service is the read/write seam between the [`CaManager`] (authoritative
//! source of CA keys and the generation counter) and the `machines` table
//! (which records what each agent has synced). It holds only cheap, clonable
//! handles and is constructed per request.

use std::sync::Arc;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use sqlx::SqlitePool;

use crate::bundle::canonical::{canonical_message, CanonicalInput};
use crate::bundle::models::{
    BundleError, BundleKey, FleetStatus, GenerationCount, RetirementAssessment, SignedBundle,
    BUNDLE_VERSION,
};
use crate::bundle::signer::BundleSigner;
use crate::ca::errors::CaError;
use crate::ca::CaManager;
use crate::clock::Clock;
use crate::machines::LivenessStatus;

/// Builds and serves signed CA bundles and the operational views around them.
#[derive(Clone)]
pub struct BundleService {
    pool: SqlitePool,
    ca: Arc<CaManager>,
    signer: Arc<dyn BundleSigner>,
    clock: Arc<dyn Clock>,
    /// Bundle validity window, in seconds (`expires_at = created_at + ttl`).
    ttl_seconds: i64,
}

impl BundleService {
    /// Construct the service from its dependencies.
    pub fn new(
        pool: SqlitePool,
        ca: Arc<CaManager>,
        signer: Arc<dyn BundleSigner>,
        clock: Arc<dyn Clock>,
        ttl_seconds: u32,
    ) -> Self {
        Self {
            pool,
            ca,
            signer,
            clock,
            ttl_seconds: i64::from(ttl_seconds.max(1)),
        }
    }

    /// The current bundle fingerprint (the value used as the HTTP `ETag`).
    pub fn current_fingerprint(&self) -> String {
        self.ca.bundle_fingerprint()
    }

    /// The current generation.
    pub fn current_generation(&self) -> u32 {
        self.ca.generation()
    }

    /// Build and sign the current bundle.
    ///
    /// The signature is computed over the canonical representation
    /// ([`canonical_message`]), never the serialized JSON. Fails closed if there
    /// are no enabled CA keys.
    pub fn build_signed_bundle(&self) -> Result<SignedBundle, BundleError> {
        let public = self.ca.get_public_bundle();
        if public.keys.is_empty() {
            return Err(BundleError::NoEnabledKeys);
        }

        let keys: Vec<BundleKey> = public
            .keys
            .into_iter()
            .map(|k| BundleKey {
                key_id: k.key_id,
                public_key: k.public_key,
                fingerprint: k.fingerprint,
            })
            .collect();

        let now = self.clock.now();
        let created_at = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        let expires_at =
            (now + Duration::seconds(self.ttl_seconds)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let algorithm = self.signer.algorithm().to_string();

        let message = canonical_message(&CanonicalInput {
            bundle_version: BUNDLE_VERSION,
            generation: public.generation,
            created_at: &created_at,
            expires_at: &expires_at,
            fingerprint: &public.fingerprint,
            keys: &keys,
        })?;

        Ok(SignedBundle {
            bundle_version: BUNDLE_VERSION,
            generation: public.generation,
            created_at,
            expires_at,
            fingerprint: public.fingerprint,
            keys,
            signature_algorithm: algorithm,
            signature: self.signer.sign_b64(&message),
            bundle_signing_public_key: self.signer.public_key_openssh(),
        })
    }

    /// Record a successful application of a bundle by `machine_id`, stamping
    /// `synced_generation`, `bundle_fingerprint`, and `last_sync`.
    ///
    /// Returns `true` if a matching machine row was updated. Only a successful
    /// outcome advances the synced state; failure/rollback outcomes are recorded
    /// purely in the audit log by the caller.
    pub async fn record_applied(
        &self,
        machine_id: &str,
        generation: i64,
        fingerprint: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let now_text = now.to_rfc3339_opts(SecondsFormat::Millis, true);
        let result = sqlx::query(
            "UPDATE machines \
             SET synced_generation = ?, bundle_fingerprint = ?, last_sync = ? \
             WHERE machine_id = ?",
        )
        .bind(generation)
        .bind(fingerprint)
        .bind(&now_text)
        .bind(machine_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Check that a machine row exists (used for non-success acks, which do not
    /// mutate sync state but must still come from a known machine).
    pub async fn machine_exists(&self, machine_id: &str) -> Result<bool, sqlx::Error> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM machines WHERE machine_id = ?")
            .bind(machine_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Compute fleet rollout metrics as of `now`.
    pub async fn fleet_status(&self, now: DateTime<Utc>) -> Result<FleetStatus, sqlx::Error> {
        let latest_generation = self.ca.generation();

        // One pass over the fleet: liveness from `last_seen`, rollout from
        // `synced_generation`.
        let rows: Vec<(Option<String>, Option<i64>)> =
            sqlx::query_as("SELECT last_seen, synced_generation FROM machines")
                .fetch_all(&self.pool)
                .await?;

        let total_machines = rows.len() as i64;
        let mut online = 0i64;
        let mut stale = 0i64;
        let mut offline = 0i64;
        let mut on_latest = 0i64;
        let mut counts: std::collections::BTreeMap<i64, i64> = std::collections::BTreeMap::new();

        for (last_seen, synced) in rows {
            let parsed = last_seen.as_deref().and_then(|s| {
                DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            });
            match LivenessStatus::derive(parsed, now) {
                LivenessStatus::Online => online += 1,
                LivenessStatus::Stale => stale += 1,
                LivenessStatus::Offline => offline += 1,
            }
            if let Some(gen) = synced {
                *counts.entry(gen).or_insert(0) += 1;
                if gen == i64::from(latest_generation) {
                    on_latest += 1;
                }
            }
        }

        let rollout_percentage = if total_machines == 0 {
            0.0
        } else {
            let pct = (on_latest as f64) * 100.0 / (total_machines as f64);
            (pct * 10.0).round() / 10.0
        };

        let oldest_generation = counts.keys().next().copied();
        let newest_generation = counts.keys().next_back().copied();
        let generations = counts
            .into_iter()
            .map(|(generation, count)| GenerationCount { generation, count })
            .collect();

        Ok(FleetStatus {
            latest_generation,
            total_machines,
            online,
            stale,
            offline,
            rollout_percentage,
            oldest_generation,
            newest_generation,
            generations,
        })
    }

    /// Assess whether the CA `id` can be safely retired.
    ///
    /// A disabled CA is **safe** to retire only when no enrolled machine still
    /// depends on it. A machine depends on the key if it synced a generation
    /// older than [`CaRecord::disabled_generation`] (the bundle it last applied
    /// still contained the key) or has never synced at all (unknown → treated
    /// conservatively as affected). An *enabled* CA is always unsafe: it must be
    /// disabled first so the published bundle stops advertising it.
    pub async fn assess_retirement(
        &self,
        id: &str,
        _now: DateTime<Utc>,
    ) -> Result<RetirementAssessment, CaError> {
        let record = self
            .ca
            .get(id)
            .ok_or_else(|| CaError::NotFound(id.to_string()))?;

        if record.enabled {
            return Ok(RetirementAssessment {
                id: record.id,
                key_id: record.key_id,
                safety: "unsafe",
                safe: false,
                affected_machines: 0,
                oldest_generation: None,
                latest_generation: None,
                reason: "CA is still enabled; disable it before retiring".to_string(),
            });
        }

        // Generation at which the key left the bundle. Defensive fallback to the
        // current generation if a legacy row predates the column.
        let cutoff = i64::from(
            record
                .disabled_generation
                .unwrap_or_else(|| self.ca.generation()),
        );

        // Machines that synced before the cutoff may still trust the key; a
        // never-synced machine (NULL) is unknown, so we count it as affected.
        let synced: Vec<Option<i64>> = sqlx::query_scalar("SELECT synced_generation FROM machines")
            .fetch_all(&self.pool)
            .await?;

        let mut affected = 0i64;
        let mut oldest: Option<i64> = None;
        let mut newest: Option<i64> = None;
        for gen in synced {
            let depends = match gen {
                None => true,
                Some(g) => g < cutoff,
            };
            if depends {
                affected += 1;
                if let Some(g) = gen {
                    oldest = Some(oldest.map_or(g, |o| o.min(g)));
                    newest = Some(newest.map_or(g, |n| n.max(g)));
                }
            }
        }

        let safe = affected == 0;
        let reason = if safe {
            "no enrolled machine depends on this key".to_string()
        } else {
            format!(
                "{affected} machine(s) synced a generation older than {cutoff} and may still trust this key"
            )
        };

        Ok(RetirementAssessment {
            id: record.id,
            key_id: record.key_id,
            safety: if safe { "safe" } else { "unsafe" },
            safe,
            affected_machines: affected,
            oldest_generation: oldest,
            latest_generation: newest,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::signer::{verify_signed_bundle, Ed25519BundleSigner};
    use crate::clock::TestClock;
    use crate::db;

    const PASS: &str = "storage-passphrase";

    fn clock() -> Arc<TestClock> {
        Arc::new(TestClock::at_rfc3339("2026-06-29T00:00:00Z").unwrap())
    }

    async fn manager(clock: Arc<dyn Clock>) -> Arc<CaManager> {
        let mgr = CaManager::in_memory(PASS, Arc::new(crate::ca::OsRandom), clock)
            .await
            .expect("manager");
        mgr.generate("ca-01", PASS).await.expect("ca");
        Arc::new(mgr)
    }

    async fn service(clock: Arc<dyn Clock>) -> (BundleService, Ed25519BundleSigner) {
        let pool = db::connect(":memory:").await.expect("connect");
        let ca = manager(clock.clone()).await;
        let signer = Arc::new(Ed25519BundleSigner::from_seed(&[5u8; 32]));
        let pinned = Ed25519BundleSigner::from_seed(&[5u8; 32]);
        (BundleService::new(pool, ca, signer, clock, 3600), pinned)
    }

    #[tokio::test]
    async fn builds_a_bundle_that_verifies() {
        let c = clock();
        let (svc, pinned) = service(c.clone() as Arc<dyn Clock>).await;
        let bundle = svc.build_signed_bundle().expect("build");
        assert_eq!(bundle.bundle_version, 1);
        assert_eq!(bundle.generation, 1);
        assert_eq!(bundle.keys.len(), 1);
        verify_signed_bundle(&bundle, &pinned.public_key_bytes(), c.now()).expect("verify");
    }

    #[tokio::test]
    async fn fingerprint_is_the_managers_fingerprint() {
        let c = clock();
        let (svc, _) = service(c.clone() as Arc<dyn Clock>).await;
        assert_eq!(svc.current_fingerprint(), svc.ca.bundle_fingerprint());
        assert!(svc
            .build_signed_bundle()
            .unwrap()
            .fingerprint
            .starts_with("sha256:"));
    }

    #[tokio::test]
    async fn empty_fleet_metrics_are_zeroed() {
        let c = clock();
        let (svc, _) = service(c.clone() as Arc<dyn Clock>).await;
        let status = svc.fleet_status(c.now()).await.expect("status");
        assert_eq!(status.total_machines, 0);
        assert_eq!(status.rollout_percentage, 0.0);
        assert_eq!(status.latest_generation, 1);
        assert!(status.generations.is_empty());
    }
}
