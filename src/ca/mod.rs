//! In-memory SSH certificate authority (CA) and certificate issuance.
//!
//! Loads an encrypted Ed25519 CA key at startup, keeps it decrypted only in
//! memory, and signs OpenSSH user certificates entirely with the `ssh-key`
//! crate — no `ssh-keygen`, no shell execution.

pub mod errors;
pub mod models;
pub mod service;

pub use errors::CaError;
pub use models::{
    CertificateRequest, CertificateResponse, CertificateValidation, DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS, MIN_TTL_SECONDS,
};
pub use service::CaService;
