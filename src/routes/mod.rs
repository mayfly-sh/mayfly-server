//! HTTP routing.
//!
//! Exposes the versioned API surface and wires in cross-cutting middleware
//! (request-id correlation). The router is intentionally minimal: only the
//! health and readiness endpoints exist at this stage.

pub mod admin;
pub mod agent;
pub mod auth;
pub mod ca_bundle;
pub mod certificates;
pub mod health;
pub mod machines;
pub mod ready;
pub mod servers;

use axum::{
    routing::{get, post},
    Router,
};

use crate::agentauth::verify_machine_signature;
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
        .route(&format!("{API_V1}/machines/enroll"), post(machines::enroll))
        .route(&format!("{API_V1}/servers"), get(servers::list_servers))
        // CA management admin API.
        .route(
            &format!("{API_V1}/admin/ca/generate"),
            post(admin::generate),
        )
        .route(&format!("{API_V1}/admin/ca/import"), post(admin::import))
        .route(
            &format!("{API_V1}/admin/ca"),
            get(admin::list),
        )
        .route(
            &format!("{API_V1}/admin/ca/{{id}}"),
            get(admin::get_one).patch(admin::patch),
        )
        .route(
            &format!("{API_V1}/admin/ca/{{id}}/retirement"),
            get(admin::retirement),
        )
        .route(
            &format!("{API_V1}/admin/ca/{{id}}/retire"),
            post(admin::retire),
        )
        .route(
            &format!("{API_V1}/admin/bundle/status"),
            get(admin::bundle_status),
        )
        // The heartbeat route is gated by the Ed25519 signature middleware via
        // `route_layer`, so only that endpoint requires a signed request.
        .merge(signed_agent_routes(state.clone()))
        .layer(axum::middleware::from_fn(propagate_request_id))
        .with_state(state)
}

/// Routes that require a verified agent signature.
///
/// `route_layer` applies the verification middleware only to these handlers
/// (not to 404s), and the layer is wired with a concrete [`AppState`] so it can
/// reach the machine registry, clock, and nonce cache.
fn signed_agent_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route(&format!("{API_V1}/agent/heartbeat"), post(agent::heartbeat))
        .route(
            &format!("{API_V1}/agent/ca-bundle"),
            get(ca_bundle::get_ca_bundle),
        )
        .route(
            &format!("{API_V1}/agent/ca-bundle/ack"),
            post(ca_bundle::ack_ca_bundle),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            verify_machine_signature,
        ))
}
