//! Machine enrollment endpoint.
//!
//! - `POST /api/v1/machines/enroll` — admit an agent with an enrollment token.
//!
//! Authentication is the enrollment token in the request body and nothing else:
//! no GitHub OAuth, no bearer token. The handler is deliberately thin — it
//! builds the [`EnrollmentService`] from shared state and delegates the entire
//! flow (validation, duplicate checks, token consumption, machine creation,
//! audit) to it. There is no SQL here.

use axum::extract::State;
use axum::Json;

use crate::bundle::with_jitter;
use crate::machines::{EnrollRequest, EnrollResponse, EnrollmentError, EnrollmentService};
use crate::state::AppState;

/// `POST /api/v1/machines/enroll` — enroll a machine using an enrollment token.
pub async fn enroll(
    State(state): State<AppState>,
    Json(request): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, EnrollmentError> {
    // The server identity returned to the agent is the CA public key, so the
    // CA must be configured for enrollment to be available.
    let ca = state.ca().ok_or_else(|| {
        EnrollmentError::internal(anyhow::anyhow!("certificate authority is not configured"))
    })?;
    let server_identity = ca
        .primary_public_key()
        .map_err(|err| EnrollmentError::internal(anyhow::Error::new(err)))?;

    // Hand the agent a per-host jittered sync interval so the fleet does not
    // poll in lockstep, plus the Bundle Signing Key to pin for verifying every
    // signed CA bundle. Jitter uses the injected CSPRNG (deterministic in tests).
    let bundle_cfg = &state.config().bundle;
    let sync_interval = with_jitter(
        bundle_cfg.sync_interval_seconds,
        bundle_cfg.jitter_percent,
        state.jitter().as_ref(),
    );
    let bundle_signing_key = state.bundle_signer().map(|s| s.public_key_openssh());

    let service = EnrollmentService::sqlite(state.db().clone(), state.clock_arc(), server_identity)
        .with_sync_interval(sync_interval)
        .with_bundle_signing_key(bundle_signing_key);
    let response = service.enroll(request).await?;
    Ok(Json(response))
}
