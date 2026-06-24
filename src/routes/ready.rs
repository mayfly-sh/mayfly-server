//! `GET /api/v1/ready` — readiness reporting.
//!
//! Currently reports only configuration readiness. The `checks` map is
//! structured so database and CA checks can be added later without changing
//! the response shape.

use axum::Json;
use serde::Serialize;

/// Readiness response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadyResponse {
    /// `"ready"` when all checks pass.
    pub status: &'static str,
    /// Individual subsystem readiness checks.
    pub checks: ReadyChecks,
}

/// Per-subsystem readiness results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadyChecks {
    /// Configuration loaded and validated.
    pub config: &'static str,
}

/// Handler for `GET /api/v1/ready`.
pub async fn ready() -> Json<ReadyResponse> {
    Json(ReadyResponse {
        status: "ready",
        checks: ReadyChecks { config: "ok" },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_expected_shape() {
        let body = ReadyResponse {
            status: "ready",
            checks: ReadyChecks { config: "ok" },
        };
        let value = serde_json::to_value(&body).expect("json");
        assert_eq!(value["status"], "ready");
        assert_eq!(value["checks"]["config"], "ok");
    }
}
