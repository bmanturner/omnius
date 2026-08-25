use std::time::Duration;

use rsk_core::ErrorCode;
use rsk_health::{CheckFailure, HealthCheckSpec};
use rsk_runtime::Criticality;

use crate::EmailService;

const HEALTH_CHECK_NAME: &str = "email-provider";
const MODULE_NAME: &str = "email";
const UNAVAILABLE_CODE: &str = "EMAIL_PROVIDER_UNAVAILABLE";

/// Builds the bounded degraded-criticality provider readiness check.
///
/// The check uses SMTP NOOP through lettre for SMTP and a value-free lifecycle probe for the test
/// sink. Provider response strings are discarded before reaching health diagnostics.
#[must_use]
pub fn email_provider_health_check(service: EmailService, timeout: Duration) -> HealthCheckSpec {
    HealthCheckSpec::new(
        HEALTH_CHECK_NAME,
        MODULE_NAME,
        Criticality::Degraded,
        timeout,
        move || {
            let service = service.clone();
            async move {
                service
                    .test_connection()
                    .await
                    .map_err(|_| CheckFailure::new(unavailable_code()))
            }
        },
    )
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static email health code must be valid")
    };
    code
}
