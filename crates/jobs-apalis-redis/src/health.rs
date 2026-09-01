use std::time::Duration;

use omnius_core::ErrorCode;
use omnius_health::{CheckFailure, HealthCheckSpec};
use omnius_jobs_core::Job;
use omnius_runtime::Criticality;

use crate::RedisJobProvider;

const MODULE_NAME: &str = "jobs-apalis-redis";
const UNAVAILABLE_CODE: &str = "REDIS_JOB_UNAVAILABLE";

/// Builds a required readiness check for one exact typed Redis job namespace.
#[must_use]
pub fn redis_job_health_check<J: Job>(
    provider: RedisJobProvider<J>,
    timeout: Duration,
) -> HealthCheckSpec {
    let check_name = format!("redis-job-{}", provider.definition().name().as_str());
    HealthCheckSpec::new(
        check_name,
        MODULE_NAME,
        Criticality::Required,
        timeout,
        move || {
            let provider = provider.clone();
            async move {
                provider
                    .diagnostics()
                    .await
                    .map(|_| ())
                    .map_err(|_| CheckFailure::new(unavailable_code()))
            }
        },
    )
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static Redis job health code must be valid")
    };
    code
}
