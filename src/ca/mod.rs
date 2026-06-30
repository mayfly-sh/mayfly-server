//! Multi-key SSH certificate authority and CA management platform.
//!
//! [`CaManager`] is the single source of truth for every CA operation:
//! certificate issuance, CA lifecycle (generate / import / enable / disable /
//! rename), usage statistics, public-bundle publication, and (in future) key
//! rotation. It manages between 1 and [`MAX_CA_KEYS`] CAs simultaneously,
//! keeping decrypted Ed25519 signers in memory and signing OpenSSH user
//! certificates entirely with the `ssh-key` crate — no `ssh-keygen`, no shell
//! execution.
//!
//! Module layout:
//! - [`models`] — request/response types, the [`CaRecord`] metadata, the public
//!   bundle, and the selection-strategy enum.
//! - [`service`] — a single signing key ([`CaKey`]): sign/verify with one key.
//! - [`store`] — persistence: the [`store::CaStore`] trait, a SQLite + on-disk
//!   implementation, an in-memory implementation, and key-set validation.
//! - [`manager`] — [`CaManager`]: lifecycle, selection, issuance, statistics,
//!   bundle, fingerprint.
//! - [`errors`] — the [`CaError`] type.
//!
//! Nothing outside [`CaManager`] iterates over CA keys or knows where they are
//! stored.

pub mod admin;
pub mod errors;
pub mod manager;
pub mod models;
pub mod service;
pub mod store;

pub use admin::{CaActivationEvent, CaStats, CaUsage, CaView, RotationResult};
pub use errors::CaError;
pub use manager::{CaManager, OsRandom, RandomSource};
pub use models::{
    validate_key_id, CaPublicKeyEntry, CaRecord, CertificateRequest, CertificateResponse,
    CertificateValidation, PublicBundle, SelectionStrategy, BOOTSTRAP_KEY_ID, DEFAULT_TTL_SECONDS,
    MAX_CA_KEYS, MAX_KEY_ID_LEN, MAX_TTL_SECONDS, MIN_TTL_SECONDS,
};
pub use service::CaKey;
pub use store::{CaStore, InMemoryCaStore, SqliteCaStore, StoredCa};
