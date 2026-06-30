//! HTTP routing.
//!
//! Exposes the versioned API surface and wires in cross-cutting middleware
//! (request-id correlation). The router is intentionally minimal: only the
//! health and readiness endpoints exist at this stage.

pub mod admin;
pub mod admin_machines;
pub mod agent;
pub mod auth;
pub mod ca_bundle;
pub mod certificates;
pub mod health;
pub mod machines;
pub mod ops;
pub mod ready;
pub mod rollout;
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
        .route(
            &format!("{API_V1}/auth/device/start"),
            post(auth::device_start),
        )
        .route(
            &format!("{API_V1}/auth/device/poll"),
            post(auth::device_poll),
        )
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
        // Guided rotation: generate a new CA + report rollout (013B).
        .route(&format!("{API_V1}/admin/ca/rotate"), post(admin::rotate))
        .route(&format!("{API_V1}/admin/ca"), get(admin::list))
        // Static read endpoints must precede `{id}`; axum 0.8 matchit gives
        // static segments priority over params, so order is not significant.
        .route(&format!("{API_V1}/admin/ca/stats"), get(admin::stats))
        .route(
            &format!("{API_V1}/admin/ca/bundle"),
            get(admin::public_bundle),
        )
        .route(
            &format!("{API_V1}/admin/ca/{{id}}"),
            get(admin::get_one)
                .patch(admin::patch)
                .delete(admin::delete_ca),
        )
        .route(
            &format!("{API_V1}/admin/ca/{{id}}/public-key"),
            get(admin::export_public_key),
        )
        .route(
            &format!("{API_V1}/admin/ca/{{id}}/enable"),
            post(admin::enable),
        )
        .route(
            &format!("{API_V1}/admin/ca/{{id}}/disable"),
            post(admin::disable),
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
        // Mint enrollment tokens (operator-only; closes BL-007). Same GitHub
        // Bearer + deny-by-default authorization as the CA admin API.
        .route(
            &format!("{API_V1}/admin/machines/enrollment-tokens"),
            post(admin::mint_enrollment_token),
        )
        // Machine administration admin API (013A). Same deny-by-default authz as
        // the CA admin API; mutations are audited; reads are not. The static
        // `enrollment-tokens` segment above takes priority over `{id}` (axum 0.8
        // matchit: static beats param).
        .route(
            &format!("{API_V1}/admin/machines"),
            get(admin_machines::list_machines),
        )
        .route(
            &format!("{API_V1}/admin/machines/{{id}}"),
            get(admin_machines::get_machine).delete(admin_machines::delete_machine),
        )
        .route(
            &format!("{API_V1}/admin/machines/{{id}}/approve"),
            post(admin_machines::approve),
        )
        .route(
            &format!("{API_V1}/admin/machines/{{id}}/disable"),
            post(admin_machines::disable),
        )
        .route(
            &format!("{API_V1}/admin/machines/{{id}}/enable"),
            post(admin_machines::enable),
        )
        .route(
            &format!("{API_V1}/admin/machines/{{id}}/revoke"),
            post(admin_machines::revoke),
        )
        .route(
            &format!("{API_V1}/admin/machines/{{id}}/reenroll"),
            post(admin_machines::reenroll),
        )
        .route(
            &format!("{API_V1}/admin/machines/{{id}}/rotate-identity"),
            post(admin_machines::rotate_identity),
        )
        // Operational console (013C): read-only audit search/stream, health,
        // status, and API metrics. Authorized deny-by-default; reads are not
        // audited (only denials are).
        .route(&format!("{API_V1}/admin/audit"), get(ops::audit_search))
        .route(
            &format!("{API_V1}/admin/audit/stream"),
            get(ops::audit_stream),
        )
        .route(&format!("{API_V1}/admin/health"), get(ops::health))
        .route(&format!("{API_V1}/admin/status"), get(ops::status))
        .route(&format!("{API_V1}/admin/metrics"), get(ops::metrics))
        // Fleet rollout console (013D): read-only rollout status, per-generation
        // breakdown, per-machine views, stuck machines, health scoring, explain,
        // timeline, and generation history. Same deny-by-default authz as the
        // operational console; reads are not audited (only denials are). Static
        // sub-paths precede the bare `/rollout` route; axum 0.8 matchit gives
        // static segments priority, so order is not significant.
        .route(&format!("{API_V1}/admin/rollout"), get(rollout::status))
        .route(
            &format!("{API_V1}/admin/rollout/generations"),
            get(rollout::generations),
        )
        .route(
            &format!("{API_V1}/admin/rollout/machines"),
            get(rollout::machines),
        )
        .route(
            &format!("{API_V1}/admin/rollout/stuck"),
            get(rollout::stuck),
        )
        .route(
            &format!("{API_V1}/admin/rollout/health"),
            get(rollout::health),
        )
        .route(
            &format!("{API_V1}/admin/rollout/explain"),
            get(rollout::explain),
        )
        .route(
            &format!("{API_V1}/admin/rollout/timeline"),
            get(rollout::timeline),
        )
        .route(
            &format!("{API_V1}/admin/rollout/history"),
            get(rollout::history),
        )
        // The heartbeat route is gated by the Ed25519 signature middleware via
        // `route_layer`, so only that endpoint requires a signed request.
        .merge(signed_agent_routes(state.clone()))
        // Record per-route request metrics for `GET /admin/metrics`. Applied with
        // `route_layer` so it runs after routing and sees the matched-path
        // template (keeps metric cardinality bounded by route, not by id).
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::ops::record_metrics,
        ))
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
