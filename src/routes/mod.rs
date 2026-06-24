//! HTTP routing.
//!
//! Exposes the versioned API surface and wires in cross-cutting middleware
//! (request-id correlation). The router is intentionally minimal: only the
//! health and readiness endpoints exist at this stage.

pub mod auth;
pub mod certificates;
pub mod health;
pub mod ready;

use axum::{
    routing::{get, post},
    Router,
};

use crate::request_id::propagate_request_id;
use crate::state::AppState;

/// API path prefix for the current version.
pub const API_V1: &str = "/api/v1";

/// Build the application router with all routes, middleware, and shared state.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route(&format!("{API_V1}/health"), get(health::health))
        .route(&format!("{API_V1}/ready"), get(ready::ready))
        .route(&format!("{API_V1}/auth/device/start"), post(auth::device_start))
        .route(&format!("{API_V1}/auth/device/poll"), post(auth::device_poll))
        .route(&format!("{API_V1}/auth/whoami"), get(auth::whoami))
        .route(
            &format!("{API_V1}/certificates/issue"),
            post(certificates::issue),
        )
        .route(
            &format!("{API_V1}/certificates/validate"),
            get(certificates::validate),
        )
        .layer(axum::middleware::from_fn(propagate_request_id))
        .with_state(state)
}
