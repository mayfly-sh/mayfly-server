//! In-memory API request metrics (ADR-0024).
//!
//! A process-local, bounded collector of per-route request counts, status-class
//! counts, and latency (min/max/avg). It is *operational telemetry*, not durable
//! audit: it resets on restart and records nothing sensitive (only the HTTP
//! method, the matched route template, the response status class, and timing).
//! It is updated by [`record_metrics`] and snapshotted by
//! `GET /api/v1/admin/metrics`.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use serde::Serialize;

use crate::state::AppState;

/// Maximum number of distinct route keys retained. Beyond this, additional
/// distinct keys are aggregated under [`OVERFLOW_KEY`] so a flood of unmatched
/// paths can never grow memory without bound.
const MAX_ROUTES: usize = 256;

/// Bucket used once [`MAX_ROUTES`] distinct keys have been recorded.
const OVERFLOW_KEY: &str = "<other>";

/// Per-route accumulator.
#[derive(Debug, Default, Clone)]
struct RouteStat {
    count: u64,
    status_2xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    total_nanos: u128,
    min_nanos: u128,
    max_nanos: u128,
}

impl RouteStat {
    fn observe(&mut self, status: u16, latency: Duration) {
        let nanos = latency.as_nanos();
        self.count += 1;
        match status {
            200..=299 => self.status_2xx += 1,
            400..=499 => self.status_4xx += 1,
            500..=599 => self.status_5xx += 1,
            _ => {}
        }
        self.total_nanos = self.total_nanos.saturating_add(nanos);
        if self.count == 1 || nanos < self.min_nanos {
            self.min_nanos = nanos;
        }
        if nanos > self.max_nanos {
            self.max_nanos = nanos;
        }
    }
}

/// Thread-safe, bounded API metrics collector.
#[derive(Debug, Default)]
pub struct ApiMetrics {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    routes: BTreeMap<String, RouteStat>,
    total_requests: u64,
}

impl ApiMetrics {
    /// Create an empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one request outcome keyed by `METHOD route-template`.
    pub fn record(&self, key: String, status: u16, latency: Duration) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            // A poisoned lock must never take down request handling; metrics are
            // best-effort telemetry.
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.total_requests += 1;
        let key = if inner.routes.contains_key(&key) || inner.routes.len() < MAX_ROUTES {
            key
        } else {
            OVERFLOW_KEY.to_string()
        };
        inner
            .routes
            .entry(key)
            .or_default()
            .observe(status, latency);
    }

    /// Take a serializable snapshot of the current metrics.
    pub fn snapshot(&self) -> ApiMetricsSnapshot {
        let inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let routes = inner
            .routes
            .iter()
            .map(|(route, s)| RouteMetric {
                route: route.clone(),
                count: s.count,
                status_2xx: s.status_2xx,
                status_4xx: s.status_4xx,
                status_5xx: s.status_5xx,
                avg_ms: if s.count == 0 {
                    0.0
                } else {
                    (s.total_nanos as f64 / s.count as f64) / 1_000_000.0
                },
                min_ms: s.min_nanos as f64 / 1_000_000.0,
                max_ms: s.max_nanos as f64 / 1_000_000.0,
            })
            .collect();
        ApiMetricsSnapshot {
            total_requests: inner.total_requests,
            routes,
        }
    }
}

/// Snapshot of API request metrics for `GET /api/v1/admin/metrics`.
#[derive(Debug, Clone, Serialize)]
pub struct ApiMetricsSnapshot {
    /// Total requests observed since startup.
    pub total_requests: u64,
    /// Per-route aggregates, ascending by route key.
    pub routes: Vec<RouteMetric>,
}

/// Per-route request statistics.
#[derive(Debug, Clone, Serialize)]
pub struct RouteMetric {
    /// `METHOD route-template`, e.g. `GET /api/v1/admin/ca/{id}`.
    pub route: String,
    /// Total requests to this route.
    pub count: u64,
    /// Responses with a 2xx status.
    pub status_2xx: u64,
    /// Responses with a 4xx status.
    pub status_4xx: u64,
    /// Responses with a 5xx status.
    pub status_5xx: u64,
    /// Mean latency in milliseconds.
    pub avg_ms: f64,
    /// Minimum observed latency in milliseconds.
    pub min_ms: f64,
    /// Maximum observed latency in milliseconds.
    pub max_ms: f64,
}

/// Axum middleware that records each request into [`AppState::metrics`].
///
/// Keyed by the matched route *template* (so dynamic ids do not explode
/// cardinality); falls back to the raw path when no template matched (e.g. a
/// 404), which is bounded by [`MAX_ROUTES`].
pub async fn record_metrics(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let start = Instant::now();
    let response = next.run(req).await;
    let latency = start.elapsed();

    state.metrics().record(
        format!("{method} {route}"),
        response.status().as_u16(),
        latency,
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_counts_and_latency() {
        let m = ApiMetrics::new();
        m.record("GET /x".into(), 200, Duration::from_millis(10));
        m.record("GET /x".into(), 500, Duration::from_millis(30));
        let snap = m.snapshot();
        assert_eq!(snap.total_requests, 2);
        assert_eq!(snap.routes.len(), 1);
        let r = &snap.routes[0];
        assert_eq!(r.count, 2);
        assert_eq!(r.status_2xx, 1);
        assert_eq!(r.status_5xx, 1);
        assert!((r.avg_ms - 20.0).abs() < 0.001);
        assert!((r.min_ms - 10.0).abs() < 0.001);
        assert!((r.max_ms - 30.0).abs() < 0.001);
    }

    #[test]
    fn bounds_distinct_routes() {
        let m = ApiMetrics::new();
        for i in 0..(MAX_ROUTES + 50) {
            m.record(format!("GET /p/{i}"), 200, Duration::from_millis(1));
        }
        let snap = m.snapshot();
        assert!(
            snap.routes.len() <= MAX_ROUTES + 1,
            "bounded + overflow bucket"
        );
        assert!(snap.routes.iter().any(|r| r.route == OVERFLOW_KEY));
        assert_eq!(snap.total_requests as usize, MAX_ROUTES + 50);
    }
}
