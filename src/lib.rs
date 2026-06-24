//! Mayfly Server — zero-trust SSH certificate authority and control plane.
//!
//! `unsafe` code is forbidden crate-wide: this is a security product and the
//! foundation has no need for it.

#![forbid(unsafe_code)]

pub mod audit;
pub mod clock;
pub mod config;
pub mod db;
pub mod errors;
pub mod logging;
pub mod request_id;
pub mod secret;
pub mod state;
