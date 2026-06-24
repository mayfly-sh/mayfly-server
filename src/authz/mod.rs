//! Config-driven, deny-by-default authorization.
//!
//! [`AuthzService`] evaluates a resolved [`Identity`] against the configured
//! allowlists and returns an [`AuthzDecision`]. It performs no I/O and depends
//! only on configuration, so it is fully testable in isolation.

pub mod errors;
pub mod models;
pub mod service;

pub use errors::AuthzError;
pub use models::{AuthzDecision, Identity};
pub use service::AuthzService;
