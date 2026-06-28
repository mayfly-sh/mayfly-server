//! Authenticated CA bundle endpoints.
//!
//! - `GET  /api/v1/agent/ca-bundle`     — fetch the current **signed** CA bundle.
//! - `POST /api/v1/agent/ca-bundle/ack` — report the outcome of applying a bundle.
//!
//! Both are authenticated by Ed25519 request signature
//! ([`crate::agentauth::verify_machine_signature`]) — there is **no** GitHub
//! auth on this path. The verified machine arrives via the
//! [`AuthenticatedMachine`] extension.
//!
//! ## Caching
//!
//! `GET` is an HTTP cache-validation endpoint. The response `ETag` is the
//! bundle fingerprint. An agent that already holds a bundle sends
//! `If-None-Match: "<fingerprint>"`; when it matches the current fingerprint the
//! server returns `304 Not Modified` with no body and does not sign or serialize
//! a bundle. Only a `200` carries a fresh signed bundle the agent must verify
//! and apply.

use axum::extract::State;
use axum::http::header::{ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::json;

use crate::agentauth::AuthenticatedMachine;
use crate::audit::NewAuditEntry;
use crate::bundle::{AckOutcome, BundleAckRequest, BundleAckResponse, BundleService};
use crate::errors::ApiError;
use crate::state::AppState;

/// Upper bound on an acknowledged fingerprint string.
const MAX_FINGERPRINT_LEN: usize = 128;

/// `GET /api/v1/agent/ca-bundle` — return the current signed bundle, or `304`
/// when the agent's `If-None-Match` already matches the current fingerprint.
pub async fn get_ca_bundle(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedMachine>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let service = require_bundle(&state)?;
    let fingerprint = service.current_fingerprint();

    // Cheap path: a matching validator means the agent is already current, so
    // skip signing/serializing entirely.
    if if_none_match_matches(&headers, &fingerprint) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        insert_etag(&mut response, &fingerprint);
        return Ok(response);
    }

    let bundle = service.build_signed_bundle().map_err(ApiError::internal)?;

    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new("bundle.downloaded", "agent")
                .with_subject(authenticated.machine.machine_id.clone())
                .with_metadata(json!({
                    "machine_id": authenticated.machine.machine_id,
                    "generation": bundle.generation,
                    "fingerprint": bundle.fingerprint,
                    "bundle_version": bundle.bundle_version,
                })),
        )
        .await?;

    let mut response = Json(&bundle).into_response();
    insert_etag(&mut response, &fingerprint);
    Ok(response)
}

/// `POST /api/v1/agent/ca-bundle/ack` — record the outcome of an apply attempt.
///
/// `status` is one of `applied` (success), `rollback` (the agent restored the
/// previous bundle after a failed `sshd` reload), or `signature_failed` (the
/// agent refused a bundle that did not verify). Only `applied` advances the
/// machine's synced generation; every outcome is audited.
pub async fn ack_ca_bundle(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedMachine>,
    Json(ack): Json<BundleAckRequest>,
) -> Result<Response, ApiError> {
    let now = state.clock().now();
    let service = require_bundle(&state)?;
    let machine_id = &authenticated.machine.machine_id;

    let outcome = AckOutcome::parse(&ack.status)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown ack status '{}'", ack.status)))?;

    if ack.generation < 0 {
        return Err(ApiError::BadRequest(
            "generation must not be negative".to_string(),
        ));
    }
    let fingerprint = ack.fingerprint.trim();
    if fingerprint.is_empty() || fingerprint.len() > MAX_FINGERPRINT_LEN {
        return Err(ApiError::BadRequest("invalid fingerprint".to_string()));
    }

    // A successful apply advances synced state; other outcomes only need the
    // machine to exist. Either way an unknown machine fails closed as auth.
    let known = if outcome.is_success() {
        service
            .record_applied(machine_id, ack.generation, fingerprint, now)
            .await
            .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?
    } else {
        service
            .machine_exists(machine_id)
            .await
            .map_err(|e| ApiError::internal(anyhow::Error::new(e)))?
    };
    if !known {
        return Err(ApiError::Unauthorized(
            "request authentication failed".to_string(),
        ));
    }

    // Sanitize the agent-supplied reason before auditing (no control chars, and
    // bounded length); it is never a secret but is attacker-influenced.
    let reason = ack.reason.as_deref().map(sanitize_reason);
    state
        .audit()
        .append_audit_event(
            NewAuditEntry::new(outcome.audit_event(), "agent")
                .with_subject(machine_id.clone())
                .with_metadata(json!({
                    "machine_id": machine_id,
                    "generation": ack.generation,
                    "fingerprint": fingerprint,
                    "reason": reason,
                })),
        )
        .await?;

    Ok(Json(BundleAckResponse {
        status: "recorded",
        generation: ack.generation,
    })
    .into_response())
}

/// The bundle service, or a 500 if the server lacks a CA manager / signing key.
fn require_bundle(state: &AppState) -> Result<BundleService, ApiError> {
    state.bundle_service().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!(
            "bundle distribution is not configured (missing CA manager or signing key)"
        ))
    })
}

/// Set a strong `ETag` header to the (quoted) bundle fingerprint.
fn insert_etag(response: &mut Response, fingerprint: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{fingerprint}\"")) {
        response.headers_mut().insert(ETAG, value);
    }
}

/// Whether `If-None-Match` matches the current fingerprint.
///
/// Accepts `*`, the bare fingerprint, or a comma-separated list of (possibly
/// weak, possibly quoted) entity tags — tolerant of how different clients
/// format the header.
fn if_none_match_matches(headers: &HeaderMap, fingerprint: &str) -> bool {
    let Some(raw) = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    raw.split(',').any(|entry| {
        let tag = entry.trim();
        if tag == "*" {
            return true;
        }
        let tag = tag.strip_prefix("W/").unwrap_or(tag);
        let tag = tag.trim().trim_matches('"');
        tag == fingerprint
    })
}

/// Strip control characters and bound the length of an agent-supplied reason.
fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}
