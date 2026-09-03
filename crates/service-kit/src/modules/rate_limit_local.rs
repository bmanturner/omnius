use std::net::SocketAddr;

use axum::{
    Router,
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use omnius_rate_limit_local::{
    LocalRateLimitPolicy, LocalRateLimiter, RateLimitIdentityKind, RateLimitOperation,
    TrustedRateLimitContext,
};

use crate::{AppCompositionBuilder, CompositionError};

pub(crate) fn register(builder: &mut AppCompositionBuilder<'_>) -> Result<(), CompositionError> {
    builder.register_capability("rate-limit-local")?;
    if !builder.runtime_available("rate-limit-local") {
        return Ok(());
    }
    let config = builder.application_rate_limit("rate-limit-local")?;
    let limiter = LocalRateLimiter::new(
        RateLimitOperation::General,
        RateLimitIdentityKind::Ip,
        LocalRateLimitPolicy {
            replenish_every: config.replenish_every,
            burst_size: config.burst_size,
            identity_buckets: config.identity_buckets,
        },
    )
    .map_err(|_| CompositionError::InvalidConfiguration {
        module: "rate-limit-local",
    })?;
    builder.register_application_rate_limiter(limiter)
}

pub(crate) fn apply(router: Router, limiter: &LocalRateLimiter) -> Router {
    limiter
        .apply(router)
        .layer(axum::middleware::from_fn(insert_trusted_context))
}

async fn insert_trusted_context(mut request: Request, next: Next) -> Response {
    if let Some(client_ip) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip())
    {
        request
            .extensions_mut()
            .insert(TrustedRateLimitContext::new(client_ip));
    }
    next.run(request).await
}
