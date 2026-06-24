//! Tamper-evident audit logging for certificate issuance.

mod hash;
mod model;
mod repository;
mod verifier;

pub use hash::{compute_entry_hash, GENESIS_PREVIOUS_HASH};
pub use model::{AuditHashInput, AuditLogEntry, NewAuditLogEntry};
pub use repository::AuditRepository;
pub use verifier::verify_chain;
