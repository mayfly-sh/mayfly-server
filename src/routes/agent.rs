//! Authenticated agent endpoints.
//!
//! - `POST /api/v1/agent/heartbeat` — liveness + telemetry from an enrolled
//!   machine.
//!
//! Authentication is by Ed25519 request signature, performed by
//! [`crate::agentauth::verify_machine_signature`] before this handler runs. The
//! verified machine arrives via the [`AuthenticatedMachine`] extension, so the
//! handler trusts the `machine_id` from the signature — never the request body.

use axum::extract::State;
use axum::{Extension, Json};

use crate::agentauth::AuthenticatedMachine;
use crate::errors::ApiError;
use crate::machines::{HeartbeatRequest, HeartbeatResponse, RegistryService};
use crate::state::AppState;

/// `POST /api/v1/agent/heartbeat` — record a heartbeat for the signed machine.
pub async fn heartbeat(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedMachine>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let now = state.clock().now();
    let service = RegistryService::sqlite(state.db().clone());
    let response = service
        .record_heartbeat(&authenticated.machine.machine_id, &request, now)
        .await?;
    Ok(Json(response))
}
