//! Request middleware for tracing and metrics

use axum::{
    middleware::Next,
    http::Request,
    response::Response,
    body::Body,
};
use sase_common::Timestamp;

/// Logging middleware
pub async fn logging(
    request: Request<Body>,
    next: Next,
) -> Response {
    let start = Timestamp::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    let elapsed = start.elapsed_micros();
    tracing::info!(
        method = %method,
        uri = %uri,
        status = %response.status(),
        latency_us = elapsed,
        "request complete"
    );

    response
}
