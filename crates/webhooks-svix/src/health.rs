use std::{sync::Arc, time::Duration};

use omnius_core::ErrorCode;
use omnius_health::{CheckFailure, HealthCheckSpec};
use omnius_runtime::Criticality;

use crate::WebhookProvider;

const HEALTH_CHECK_NAME: &str = "svix";
const MODULE_NAME: &str = "webhooks-svix";
const UNAVAILABLE_CODE: &str = "SVIX_PROVIDER_UNAVAILABLE";

/// Builds the bounded degraded-criticality Svix readiness check.
///
/// Provider errors and bodies are discarded before health diagnostics leave the crate.
#[must_use]
pub fn svix_health_check<P>(provider: Arc<P>, timeout: Duration) -> HealthCheckSpec
where
    P: WebhookProvider + ?Sized,
{
    HealthCheckSpec::new(
        HEALTH_CHECK_NAME,
        MODULE_NAME,
        Criticality::Degraded,
        timeout,
        move || {
            let provider = Arc::clone(&provider);
            async move {
                provider
                    .health()
                    .await
                    .map_err(|_| CheckFailure::new(unavailable_code()))
            }
        },
    )
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static Svix health code must be valid")
    };
    code
}
