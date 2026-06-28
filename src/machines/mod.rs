//! Machine enrollment.
//!
//! An operator mints a single-use enrollment token; an agent presents that
//! token together with its hostname and Ed25519 public key; the server
//! validates everything, atomically consumes the token, creates the machine,
//! audits `machine.enrolled`, and returns the machine's id, suggested
//! intervals, and the server's identity (CA public key).
//!
//! Layering mirrors the rest of the codebase:
//! - [`models`] — domain types and HTTP DTOs.
//! - [`token`] — token generation, SHA-256 hashing, constant-time comparison.
//! - [`validation`] — hostname and Ed25519 public-key validation.
//! - [`repository`] — the repository traits and their SQLite implementations.
//! - [`service`] — the single-transaction enrollment flow.
//! - [`errors`] — [`EnrollmentError`] and its HTTP representation.

pub mod errors;
pub mod models;
pub mod protocol;
pub mod repository;
pub mod service;
pub mod token;
pub mod validation;

pub use errors::EnrollmentError;
pub use models::{
    EnrollRequest, EnrollResponse, EnrollmentToken, IssuedEnrollmentToken, Machine, MachineStatus,
    NewEnrollmentToken, NewMachine,
};
pub use protocol::{
    HeartbeatRequest, HeartbeatResponse, LivenessStatus, RegistryError, RegistryService,
    ServerSummary,
};
pub use repository::{
    EnrollmentTokenRepository, HeartbeatUpdate, MachineRepository, SqliteEnrollmentTokenRepository,
    SqliteMachineRepository,
};
pub use service::{
    EnrollmentService, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_SYNC_INTERVAL, EVENT_MACHINE_ENROLLED,
};
