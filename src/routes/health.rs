//! `GET /api/v1/health` — liveness and version reporting.

use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::AppState;

/// Compile-time crate version reported in the health response.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Health response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthResponse {
    /// Always `"ok"` when the process is serving.
    pub status: &'static str,
    /// Crate version (`CARGO_PKG_VERSION`).
    pub version: &'static str,
    /// Seconds since the server finished initialization.
    pub uptime_seconds: u64,
}

/// Compute uptime in whole seconds from application state.
///
/// Uses the injected clock (deterministic under test) and is non-negative
/// because [`AppState::uptime`](crate::state::AppState::uptime) is clamped.
pub fn uptime_seconds(state: &AppState) -> u64 {
    state.uptime().num_seconds().max(0) as u64
}

/// Handler for `GET /api/v1/health`.
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: VERSION,
        uptime_seconds: uptime_seconds(&state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, TestClock};
    use crate::config::Config;
    use chrono::TimeDelta;
    use std::sync::Arc;

    async fn state_with(clock: Arc<dyn Clock>) -> AppState {
        let pool = crate::db::connect(":memory:").await.expect("db");
        let mut config = Config::default();
        config.server.tls.enabled = false;
        AppState::new(config, pool, clock)
    }

    #[test]
    fn serializes_expected_shape() {
        let body = HealthResponse {
            status: "ok",
            version: VERSION,
            uptime_seconds: 42,
        };
        let value = serde_json::to_value(&body).expect("json");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["version"], VERSION);
        assert_eq!(value["uptime_seconds"], 42);
    }

    #[tokio::test]
    async fn uptime_seconds_uses_clock() {
        let clock = Arc::new(TestClock::at_rfc3339("2026-06-24T12:00:00Z").unwrap());
        let state = state_with(clock.clone() as Arc<dyn Clock>).await;
        assert_eq!(uptime_seconds(&state), 0);
        clock.advance(TimeDelta::seconds(123));
        assert_eq!(uptime_seconds(&state), 123);
    }
}
