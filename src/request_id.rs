//! Request correlation via per-request identifiers.
//!
//! The [`propagate_request_id`] middleware gives every request a server-owned,
//! collision-resistant identifier that is:
//! - made available to handlers via the [`RequestId`] request extension,
//! - attached to a tracing span so all logs for the request are correlated,
//! - echoed back to the client in the `X-Request-Id` response header.
//!
//! ## Trust boundary (zero-trust)
//!
//! The canonical [`RequestId`] is **always** a freshly generated UUIDv7. A
//! client-supplied `X-Request-Id` is never adopted as the canonical id, because
//! doing so would let a caller force correlation-id collisions or impersonate
//! another request's id in our logs and audit trail.
//!
//! For interoperability with upstream tracing, a client-supplied value that
//! passes [`is_acceptable_id`] (short, ASCII alphanumeric/`-`, preventing
//! log-injection / CRLF and unbounded-length abuse) is recorded separately on
//! the span as `upstream_request_id`. It is informational only.
//!
//! ## Log level
//!
//! Correlation relies on the request span being enabled. The span is created at
//! `INFO`; run the server at `info` verbosity or lower-threshold so that
//! `warn`/`error` events emitted within a request inherit `request_id`.

use std::sync::LazyLock;

use axum::{
    extract::Request,
    http::{header::HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;
use uuid::Uuid;

/// Canonical header name used for request correlation.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Pre-parsed header name, reused for every response.
static REQUEST_ID_HEADER_NAME: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static(REQUEST_ID_HEADER));

/// Maximum accepted length of a client-supplied request id.
const MAX_REQUEST_ID_LEN: usize = 128;

/// A per-request correlation identifier, stored in request extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

impl RequestId {
    /// Borrow the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a client-supplied request id is safe to reuse.
///
/// Accepts only non-empty, reasonably short tokens composed of ASCII
/// alphanumerics and `-`. This deliberately excludes whitespace and control
/// characters to prevent log injection.
fn is_acceptable_id(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= MAX_REQUEST_ID_LEN
        && candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Extract a sanitized, client-supplied correlation hint, if any.
///
/// Returns `None` when no header is present or it fails [`is_acceptable_id`].
/// This value is informational only and never becomes the canonical id.
fn upstream_request_id(req: &Request) -> Option<String> {
    req.headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|candidate| is_acceptable_id(candidate))
        .map(str::to_string)
}

/// Axum middleware that establishes request-id correlation.
pub async fn propagate_request_id(mut req: Request, next: Next) -> Response {
    // Canonical id is always server-generated and collision-resistant.
    let request_id = Uuid::now_v7().to_string();
    let upstream = upstream_request_id(&req);

    req.extensions_mut().insert(RequestId(request_id.clone()));

    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        upstream_request_id = upstream.as_deref().unwrap_or("none"),
    );

    let mut response = next.run(req).instrument(span).await;

    // The id is a freshly generated UUID, so it is always a valid header value;
    // fall back silently if that ever changes.
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(REQUEST_ID_HEADER_NAME.clone(), value);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Extension, routing::get, Router};
    use tower::ServiceExt;

    async fn echo_request_id(Extension(id): Extension<RequestId>) -> String {
        id.0
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(echo_request_id))
            .layer(axum::middleware::from_fn(propagate_request_id))
    }

    async fn body_string(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    #[test]
    fn rejects_unsafe_ids() {
        assert!(!is_acceptable_id(""));
        assert!(!is_acceptable_id("has space"));
        assert!(!is_acceptable_id("inject\r\nLOG"));
        assert!(!is_acceptable_id(&"a".repeat(MAX_REQUEST_ID_LEN + 1)));
    }

    #[test]
    fn accepts_safe_ids() {
        assert!(is_acceptable_id("abc-123"));
        assert!(is_acceptable_id(&Uuid::now_v7().to_string()));
    }

    #[test]
    fn upstream_extraction_sanitizes() {
        let with_header = |val: &str| {
            let req = Request::builder()
                .uri("/")
                .header(REQUEST_ID_HEADER, val)
                .body(Body::empty())
                .unwrap();
            upstream_request_id(&req)
        };

        assert_eq!(with_header("trace-abc-1"), Some("trace-abc-1".to_string()));
        assert_eq!(with_header("unsafe id"), None);

        let no_header = Request::builder().uri("/").body(Body::empty()).unwrap();
        assert_eq!(upstream_request_id(&no_header), None);
    }

    #[tokio::test]
    async fn generates_uuidv7_when_header_absent() {
        let response = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .expect("response");

        let header = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("header present")
            .to_str()
            .expect("ascii")
            .to_string();

        let body = body_string(response).await;
        assert_eq!(header, body, "extension and header must match");

        let parsed = Uuid::parse_str(&body).expect("valid uuid");
        assert_eq!(parsed.get_version_num(), 7, "must be UUIDv7");
    }

    #[tokio::test]
    async fn does_not_adopt_client_supplied_id() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, "client-correlation-42")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        let header = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("header")
            .to_str()
            .unwrap()
            .to_string();

        // The canonical id must be our own UUIDv7, not the client's value.
        assert_ne!(header, "client-correlation-42");
        let body = body_string(response).await;
        assert_eq!(header, body);
        let parsed = Uuid::parse_str(&body).expect("server-generated uuid");
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[tokio::test]
    async fn ignores_unsafe_client_supplied_id() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, "unsafe id with spaces")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        let body = body_string(response).await;
        assert_ne!(body, "unsafe id with spaces");
        let parsed = Uuid::parse_str(&body).expect("generated uuid");
        assert_eq!(parsed.get_version_num(), 7);
    }

    /// A tracing layer that records the fields of every created span, so we can
    /// assert that request correlation fields are attached.
    #[derive(Clone, Default)]
    struct SpanFieldCapture {
        spans: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanFieldCapture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor(String);
            impl tracing::field::Visit for Visitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!("{}={:?};", field.name(), value));
                }
            }
            let mut visitor = Visitor(String::new());
            attrs.record(&mut visitor);
            if let Ok(mut spans) = self.spans.lock() {
                spans.push(format!("{} {}", attrs.metadata().name(), visitor.0));
            }
        }
    }

    #[tokio::test]
    async fn request_span_carries_correlation_fields() {
        use tracing_subscriber::layer::SubscriberExt;

        let capture = SpanFieldCapture::default();
        let spans = capture.spans.clone();
        let subscriber = tracing_subscriber::registry().with(capture);

        let _guard = tracing::subscriber::set_default(subscriber);
        // Sibling tests may drive the router with no subscriber installed,
        // caching this span's callsite interest as "disabled". Force a
        // re-evaluation against the capture subscriber now that it is the
        // current default so the span is observed regardless of test ordering.
        tracing::callsite::rebuild_interest_cache();

        let _ = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, "trace-from-gateway")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");

        let recorded = spans.lock().expect("lock").clone();
        let request_span = recorded
            .iter()
            .find(|line| line.starts_with("request "))
            .expect("request span recorded");

        assert!(request_span.contains("request_id="));
        assert!(
            request_span.contains("upstream_request_id="),
            "upstream hint should be recorded: {request_span}"
        );
        assert!(request_span.contains("trace-from-gateway"));
    }
}
