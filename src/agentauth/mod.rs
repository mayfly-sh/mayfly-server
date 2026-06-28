//! Agent request-authentication protocol: canonical signing, replay protection,
//! and the verification middleware.
//!
//! Machines authenticate every request with their own Ed25519 identity key —
//! there are no API keys, shared secrets, or bearer tokens on this path. The
//! pieces are intentionally small and independently testable:
//!
//! * [`signing`] — the canonical string, body hashing, and signature
//!   verification (the byte-for-byte contract shared with the agent).
//! * [`nonce`] — the replay cache trait and its in-memory implementation.
//! * [`middleware`] — the Axum layer that ties them together and produces an
//!   [`middleware::AuthenticatedMachine`] for handlers.

pub mod middleware;
pub mod nonce;
pub mod signing;

pub use middleware::{verify_machine_signature, AuthenticatedMachine};
pub use nonce::{InMemoryNonceCache, NonceCache};
