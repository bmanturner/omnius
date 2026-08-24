use std::time::Duration;

use rsk_core::ErrorCode;
use rsk_health::{CheckFailure, HealthCheckSpec};
use rsk_postgres::PostgresPool;
use rsk_runtime::Criticality;

const HEALTH_CHECK_NAME: &str = "session-store";
const MODULE_NAME: &str = "auth-session-postgres";
const UNAVAILABLE_CODE: &str = "SESSION_STORE_UNAVAILABLE";

/// Builds the required readiness check for provider and metadata persistence.
#[must_use]
pub fn session_store_health_check(pool: PostgresPool, timeout: Duration) -> HealthCheckSpec {
    HealthCheckSpec::new(
        HEALTH_CHECK_NAME,
        MODULE_NAME,
        Criticality::Required,
        timeout,
        move || {
            let pool = pool.clone();
            async move {
                let healthy = match pool.acquire().await {
                    Ok(mut connection) => sqlx::query_scalar::<_, bool>(
                        "SELECT to_regclass('tower_sessions.session') IS NOT NULL \
                         AND to_regclass('sessions') IS NOT NULL",
                    )
                    .fetch_one(&mut *connection)
                    .await
                    .unwrap_or(false),
                    Err(_) => false,
                };
                if healthy {
                    Ok(())
                } else {
                    Err(CheckFailure::new(unavailable_code()))
                }
            }
        },
    )
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static session health code must be valid")
    };
    code
}
