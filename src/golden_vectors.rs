//! Cross-repository golden protocol vectors — server side (BL-026, milestone 009D).
//!
//! These tests load the byte-identical golden vectors vendored from the single
//! canonical source (`.cursor/contracts/golden/protocol-vectors.json`) and
//! recompute every value from the server's **real** canonical functions, asserting
//! equality. The agent runs an independent mirror of these checks against the
//! same bytes. If either repository's canonicalization, fingerprinting, ETag,
//! signing payload, or request-signature verification ever drifts, its golden
//! test fails — guaranteeing permanent cross-repository protocol compatibility.
//!
//! No serialization mocks: the vectors flow through the production code paths
//! (`bundle::canonical::canonical_message`, `ca::manager::bundle_fingerprint`,
//! `routes::ca_bundle::etag_value`, `agentauth::signing::*`). No literals are
//! duplicated: every expected value lives only in the vendored JSON.
//!
//! The agent↔helper IPC framing vector is intentionally not exercised here: the
//! server is not a party to that protocol. It is validated by the agent (the
//! in-scope consumer) and the `mayfly-helper` repository.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::agentauth::signing::{
    body_sha256_hex, canonical_string, verify_signature, SIGNING_DOMAIN,
};
use crate::bundle::canonical::{canonical_message, CanonicalInput};
use crate::bundle::models::BundleKey;
use crate::ca::manager::bundle_fingerprint;
use crate::ca::models::CaPublicKeyEntry;
use crate::routes::ca_bundle::etag_value;

/// The vendored, byte-identical copy of the canonical golden vectors.
const VECTORS_JSON: &str = include_str!("../tests/vectors/protocol-vectors.json");

/// Per-key fingerprints are not part of the canonical bundle bytes, so the
/// golden vectors omit them; any placeholder is fine here.
const UNUSED_KEY_FP: &str = "SHA256:unused";

#[derive(Deserialize)]
struct Vectors {
    signing_domain: String,
    bundle: BundleVectors,
    request_signing: RequestSigningVectors,
}

#[derive(Deserialize)]
struct KeyVector {
    key_id: String,
    public_key: String,
}

#[derive(Deserialize)]
struct BundleVectors {
    bundle_version: u32,
    generation: u32,
    created_at: String,
    expires_at: String,
    signature_algorithm: String,
    keys: Vec<KeyVector>,
    fingerprint: String,
    etag: String,
    signing_key: String,
    signing_payload: String,
    signature: String,
}

#[derive(Deserialize)]
struct RequestSigningVectors {
    machine_id: String,
    timestamp: i64,
    nonce: String,
    method: String,
    path: String,
    body: String,
    body_sha256: String,
    canonical_string: String,
    machine_public_key: String,
    signature: String,
    minimal_canonical_string: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS_JSON).expect("golden vectors must parse")
}

fn bundle_keys(keys: &[KeyVector]) -> Vec<BundleKey> {
    keys.iter()
        .map(|k| BundleKey {
            key_id: k.key_id.clone(),
            public_key: k.public_key.clone(),
            fingerprint: UNUSED_KEY_FP.to_string(),
        })
        .collect()
}

fn ca_entries(keys: &[KeyVector]) -> Vec<CaPublicKeyEntry> {
    keys.iter()
        .map(|k| CaPublicKeyEntry {
            key_id: k.key_id.clone(),
            public_key: k.public_key.clone(),
            fingerprint: UNUSED_KEY_FP.to_string(),
        })
        .collect()
}

#[test]
fn signing_domain_matches() {
    assert_eq!(vectors().signing_domain, SIGNING_DOMAIN);
}

#[test]
fn bundle_fingerprint_and_etag_match() {
    let b = vectors().bundle;
    // Matching the fingerprint hash transitively proves the server's canonical
    // fingerprint bytes equal the agent's `fingerprint_payload` (same SHA-256).
    let fp = bundle_fingerprint(b.generation, &ca_entries(&b.keys));
    assert_eq!(fp, b.fingerprint);
    assert_eq!(etag_value(&fp), b.etag);
}

#[test]
fn bundle_signing_payload_matches() {
    let b = vectors().bundle;
    assert_eq!(b.signature_algorithm, "ssh-ed25519");
    let keys = bundle_keys(&b.keys);
    let bytes = canonical_message(&CanonicalInput {
        bundle_version: b.bundle_version,
        generation: b.generation,
        created_at: &b.created_at,
        expires_at: &b.expires_at,
        fingerprint: &b.fingerprint,
        keys: &keys,
    })
    .unwrap();
    assert_eq!(String::from_utf8(bytes).unwrap(), b.signing_payload);
}

#[test]
fn signed_bundle_signature_verifies() {
    let b = vectors().bundle;
    let key = ssh_key::PublicKey::from_openssh(&b.signing_key).unwrap();
    let ed = key.key_data().ed25519().unwrap();
    let vk = VerifyingKey::from_bytes(&ed.0).unwrap();
    let sig_bytes: [u8; 64] = BASE64.decode(&b.signature).unwrap().try_into().unwrap();
    let signature = Signature::from_bytes(&sig_bytes);
    // The signature is over the canonical signing payload bytes.
    vk.verify_strict(b.signing_payload.as_bytes(), &signature)
        .expect("golden bundle signature must verify (verify_strict)");
}

#[test]
fn request_signing_canonical_strings_match() {
    let r = vectors().request_signing;
    assert_eq!(body_sha256_hex(r.body.as_bytes()), r.body_sha256);
    let canonical = canonical_string(
        &r.machine_id,
        r.timestamp,
        &r.nonce,
        &r.method,
        &r.path,
        &r.body_sha256,
    );
    assert_eq!(canonical, r.canonical_string);
    assert_eq!(
        canonical_string("m", 5, "n", "POST", "/p", "deadbeef"),
        r.minimal_canonical_string
    );
}

#[test]
fn request_signature_verifies() {
    let r = vectors().request_signing;
    verify_signature(&r.machine_public_key, &r.canonical_string, &r.signature)
        .expect("golden request signature must verify (verify_strict)");
}
