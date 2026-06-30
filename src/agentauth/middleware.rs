//! Axum middleware that authenticates an agent request by its Ed25519
//! signature, then hands the verified [`AuthenticatedMachine`] to the handler
//! via request extensions.
//!
//! Verification order is deliberate and fail-closed:
//!
//! 1. All four signing headers must be present and well-formed.
//! 2. The timestamp must be within [`TIMESTAMP_SKEW_SECS`] of the server clock.
//! 3. The body is buffered (bounded by [`MAX_SIGNED_BODY_BYTES`]) and hashed.
//! 4. The named machine must exist; its stored public key is loaded.
//! 5. The Ed25519 signature must verify over the canonical string.
//! 6. Only then is the nonce consumed — so an unauthenticated attacker cannot
//!    flood the replay cache, and a valid signature is required before any
//!    state (the nonce entry) is written.
//!
//! Any failure returns `401 Unauthorized` with a generic message; the specific
//! reason is logged server-side (never the signature bytes or body).

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::request::Parts,
    middleware::Next,
    response::Response,
};

use crate::errors::ApiError;
use crate::machines::models::{Machine, MachineStatus};
use crate::machines::repository::{MachineRepository, SqliteMachineRepository};
use crate::state::AppState;

use super::signing;

/// Maximum allowed signed-request body. Heartbeats are tiny; this is a generous
/// ceiling that still bounds memory and hashing work per request.
pub const MAX_SIGNED_BODY_BYTES: usize = 64 * 1024;

/// Maximum accepted clock skew between agent and server, in seconds.
pub const TIMESTAMP_SKEW_SECS: i64 = 60;

/// A machine whose request signature has been fully verified.
///
/// Inserted into request extensions by [`verify_machine_signature`] and read by
/// handlers via `Extension<AuthenticatedMachine>`. Its presence is proof the
/// request was signed by the private key matching the stored public key.
#[derive(Debug, Clone)]
pub struct AuthenticatedMachine {
    /// The verified machine record.
    pub machine: Machine,
}

/// Generic client-facing rejection. Specifics are logged, never returned.
fn reject() -> ApiError {
    ApiError::Unauthorized("request authentication failed".to_string())
}

/// Read a required signing header as a `&str`, or reject.
fn header_value<'a>(parts: &'a Parts, name: &str) -> Result<&'a str, ApiError> {
    parts
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            tracing::debug!(header = name, "signed request missing or malformed header");
            ApiError::Unauthorized("missing or malformed signing headers".to_string())
        })
}

/// Middleware: verify the agent signature and attach [`AuthenticatedMachine`].
pub async fn verify_machine_signature(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();

    let machine_id = header_value(&parts, signing::HEADER_MACHINE_ID)?.to_string();
    let timestamp_raw = header_value(&parts, signing::HEADER_TIMESTAMP)?;
    let nonce = header_value(&parts, signing::HEADER_NONCE)?.to_string();
    let signature = header_value(&parts, signing::HEADER_SIGNATURE)?.to_string();

    let timestamp: i64 = timestamp_raw.parse().map_err(|_| {
        tracing::debug!(%machine_id, "signed request has non-integer timestamp");
        reject()
    })?;

    // (2) Timestamp window. Checked before any DB work so stale/forged requests
    // are cheap to reject.
    let now = state.clock().now();
    if (now.timestamp() - timestamp).abs() > TIMESTAMP_SKEW_SECS {
        tracing::debug!(%machine_id, "signed request timestamp outside window");
        return Err(reject());
    }

    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();

    // (3) Buffer and hash the body. `to_bytes` enforces the size ceiling.
    let body_bytes: Bytes = axum::body::to_bytes(body, MAX_SIGNED_BODY_BYTES)
        .await
        .map_err(|_| {
            tracing::debug!(%machine_id, "signed request body unreadable or too large");
            reject()
        })?;
    let body_hash = signing::body_sha256_hex(&body_bytes);

    // (4) The machine must exist; load its public key.
    let mut conn = state
        .db()
        .acquire()
        .await
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;
    let machine = SqliteMachineRepository
        .find_by_id(&mut conn, &machine_id)
        .await
        .map_err(|err| ApiError::internal(anyhow::Error::new(err)))?;
    let Some(machine) = machine else {
        tracing::debug!(%machine_id, "signed request for unknown machine");
        return Err(reject());
    };
    drop(conn);

    // (5) Verify the signature over the canonical string.
    let canonical =
        signing::canonical_string(&machine_id, timestamp, &nonce, &method, &path, &body_hash);
    if let Err(err) = signing::verify_signature(&machine.public_key, &canonical, &signature) {
        tracing::debug!(%machine_id, reason = %err, "signed request failed signature check");
        return Err(reject());
    }

    // (5b) Lifecycle gate (deny-by-default): only an ACTIVE machine may act.
    // A disabled/revoked/pending machine is rejected here — this is how the
    // operator `machine disable`/`revoke` lifecycle takes effect on the agent's
    // next signed request without any agent change (ADR-0022). The check runs
    // after signature verification so only an authenticated machine learns its
    // state, and the rejection is the same generic 401 (no status enumeration).
    if machine.status != MachineStatus::Active {
        tracing::debug!(
            %machine_id,
            status = machine.status.as_str(),
            "signed request from a non-active machine rejected",
        );
        return Err(reject());
    }

    // (6) Consume the nonce last: only valid signatures may write to the cache.
    if !state
        .nonce_cache()
        .check_and_record(&machine_id, &nonce, now)
    {
        tracing::debug!(%machine_id, %nonce, "signed request replays a nonce");
        return Err(reject());
    }

    parts.extensions.insert(AuthenticatedMachine { machine });
    let request = axum::extract::Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(request).await)
}
