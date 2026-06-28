//! GitHub integration: device-flow authentication and identity lookup.
//!
//! All GitHub access goes through the [`GitHubClient`] trait so handlers are
//! testable without network access and GitHub calls are never made directly
//! from the HTTP layer.

pub mod client;
pub mod errors;
pub mod models;

pub use client::{GitHubClient, RealGitHubClient, UnconfiguredGitHubClient};
pub use errors::GitHubError;
pub use models::{
    DeviceAuthorization, DevicePollRequest, DeviceTokenOutcome, GitHubUser, PollResponse,
    WhoamiResponse,
};
