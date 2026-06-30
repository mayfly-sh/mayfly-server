//! Fleet rollout management (013D / ADR-0025).
//!
//! A read-only composition layer that turns the machine registry, the CA
//! generation counter, and the append-only audit log into the operator-facing
//! rollout views the CLI renders. It owns **no persistence and no write path**;
//! see [`service::RolloutService`] for the derivations and [`models`] for the
//! serialized DTOs.

pub mod models;
pub mod service;

pub use models::{
    ExplainCategory, GenerationDetail, GenerationHistory, GenerationsResponse, MachineFailure,
    MachineRollout, MachinesResponse, RolloutBreakdown, RolloutEta, RolloutExplanation,
    RolloutHealth, RolloutHistory, RolloutStatus, RolloutTimeline, StuckMachine, StuckReport,
    TimelineEvent,
};
pub use service::{RolloutError, RolloutService, TIMELINE_DEFAULT_LIMIT, TIMELINE_MAX_LIMIT};
