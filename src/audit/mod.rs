//! Tamper-evident, append-only audit log.
//!
//! Layering:
//! - [`model`] — domain types (`AuditEntry`, `NewAuditEntry`, `AuditTip`,
//!   `AuditVerificationResult`).
//! - [`hash`] — deterministic canonicalization and SHA-256 chain hashing.
//! - [`verifier`] — pure chain verification over a slice of entries.
//! - [`repository`] — append-only SQLite persistence.
//! - [`service`] — clock-stamped append, tip lookup, and verification.

pub mod hash;
pub mod model;
pub mod repository;
pub mod service;
pub mod verifier;

pub use hash::{canonicalize, compute_entry_hash, hashes_equal, GENESIS_PREVIOUS_HASH};
pub use model::{AuditEntry, AuditTip, AuditVerificationResult, NewAuditEntry};
pub use repository::AuditRepository;
pub use service::AuditService;
pub use verifier::verify_chain;
