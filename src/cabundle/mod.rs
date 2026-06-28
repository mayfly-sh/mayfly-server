//! CA bundle distribution.
//!
//! The server owns the set of SSH User CA public keys that agents trust. This
//! module assembles the **current bundle** (the enabled keys plus a monotonic
//! generation), computes a stable fingerprint over its canonical JSON, and
//! records each agent's acknowledgement of a synced generation.
//!
//! Layering mirrors the rest of the codebase:
//! - [`models`] — DTOs, validation, canonical JSON, and fingerprinting.
//! - [`repository`] — the key-store trait and its SQLite implementation.
//! - [`service`] — bundle assembly, seeding, and acknowledgement.
//!
//! Route concerns (the `If-Generation` header, `304 Not Modified`) live in
//! [`crate::routes::ca_bundle`], never here.

pub mod models;
pub mod repository;
pub mod service;

pub use models::{
    canonical_json, compute_fingerprint, AckError, AckRequest, AckResponse, CaBundle,
    CaBundleError, CaBundleKey, CaKeyRecord, MAX_CA_KEYS, MIN_CA_KEYS,
};
pub use repository::{CaKeyRepository, SqliteCaKeyRepository};
pub use service::CaBundleService;
