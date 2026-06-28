//! Mayfly Server — zero-trust SSH certificate authority and control plane.
//!
//! `unsafe` code is forbidden crate-wide: this is a security product and the
//! foundation has no need for it.

#![forbid(unsafe_code)]

pub mod agentauth;
pub mod audit;
pub mod authz;
pub mod bundle;
pub mod ca;
pub mod cabundle;
pub mod clock;
pub mod config;
pub mod db;
pub mod dev_certs;
pub mod environment;
pub mod errors;
pub mod github;
pub mod logging;
pub mod machines;
pub mod request_id;
pub mod routes;
pub mod secret;
pub mod server;
pub mod state;
pub mod tls;
