//! Operational telemetry primitives for the operator console (013C / ADR-0024).
//!
//! - [`metrics`] — in-memory, bounded API request metrics + the recording
//!   middleware. These back `GET /api/v1/admin/metrics` and the API-statistics
//!   summary in `GET /api/v1/admin/status`.
//!
//! Audit *search* (the read-only query layer over the append-only log) lives in
//! [`crate::audit::query`]; health/status rollups are assembled in
//! [`crate::routes::ops`] from the existing services.

pub mod metrics;

pub use metrics::{record_metrics, ApiMetrics, ApiMetricsSnapshot, RouteMetric};
