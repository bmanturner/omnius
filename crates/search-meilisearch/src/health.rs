use std::{sync::Arc, time::Duration};

use rsk_core::ErrorCode;
use rsk_health::{CheckFailure, HealthCheckSpec};
use rsk_runtime::Criticality;
use time::OffsetDateTime;

use crate::{IndexSchema, ReindexStore, SearchProvider};

const HEALTH_CHECK_NAME: &str = "search-provider";
const MODULE_NAME: &str = "search-meilisearch";
const UNAVAILABLE_CODE: &str = "SEARCH_PROVIDER_UNAVAILABLE";

/// Builds the degraded readiness check for provider connectivity, schema marker, and projection age.
#[must_use]
pub fn search_provider_health_check(
    provider: Arc<dyn SearchProvider>,
    store: Arc<dyn ReindexStore>,
    schema: IndexSchema,
    timeout: Duration,
    stale_after: Duration,
) -> HealthCheckSpec {
    HealthCheckSpec::new(
        HEALTH_CHECK_NAME,
        MODULE_NAME,
        Criticality::Degraded,
        timeout,
        move || {
            let provider = Arc::clone(&provider);
            let store = Arc::clone(&store);
            let schema = schema.clone();
            async move {
                let (provider_result, freshness_result) =
                    tokio::join!(provider.health(&schema), store.freshness(schema.alias()));
                let healthy = match (provider_result, freshness_result) {
                    (Ok(()), Ok(freshness)) => {
                        let anchor = freshness
                            .last_projected_at
                            .map_or(freshness.activated_at, |projected_at| {
                                projected_at.max(freshness.activated_at)
                            });
                        time::Duration::try_from(stale_after)
                            .ok()
                            .and_then(|maximum_age| anchor.checked_add(maximum_age))
                            .is_some_and(|deadline| OffsetDateTime::now_utc() <= deadline)
                    }
                    _ => false,
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
        unreachable!("static search health code must be valid")
    };
    code
}
