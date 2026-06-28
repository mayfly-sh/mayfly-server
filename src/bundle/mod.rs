//! Signed CA bundle distribution.
//!
//! This module hardens the agent-facing CA trust distribution path into a
//! production-grade protocol on top of the [`crate::ca::CaManager`]:
//!
//! - [`models::SignedBundle`] — a versioned, signed trust artifact carrying the
//!   enabled CA public keys plus authenticity (signature) and freshness
//!   (`created_at`/`expires_at`) metadata.
//! - [`canonical`] — one explicit, version-specific byte layout that is signed
//!   and verified on both sides (never serialized JSON).
//! - [`signer`] — the dedicated Ed25519 Bundle Signing Key (distinct from the
//!   SSH CA keys) and fail-closed verification.
//! - [`jitter`] — CSPRNG-backed polling-interval jitter to avoid synchronized
//!   fleet polling.
//! - [`service::BundleService`] — builds/signs bundles, records agent
//!   acknowledgements, computes fleet rollout metrics, and assesses CA
//!   retirement safety.
//!
//! The bundle *fingerprint* identifies a bundle (and is the HTTP `ETag`); the
//! *signature* authenticates it. They are independent and both are preserved.

pub mod canonical;
pub mod jitter;
pub mod models;
pub mod service;
pub mod signer;

pub use jitter::with_jitter;
pub use models::{
    AckOutcome, BundleAckRequest, BundleAckResponse, BundleError, BundleKey, FleetStatus,
    GenerationCount, RetirementAssessment, SignedBundle, BUNDLE_VERSION, SIGNATURE_ALGORITHM,
};
pub use service::BundleService;
pub use signer::{verify_signed_bundle, BundleSigner, Ed25519BundleSigner};
