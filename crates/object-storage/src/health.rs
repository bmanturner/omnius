use std::time::Duration;

use omnius_core::ErrorCode;
use omnius_health::{CheckFailure, HealthCheckSpec};
use omnius_runtime::Criticality;

use crate::BlobStore;

const HEALTH_CHECK_NAME: &str = "object-store";
const MODULE_NAME: &str = "object-storage";
const UNAVAILABLE_CODE: &str = "OBJECT_STORE_UNAVAILABLE";

/// Builds the bounded degraded-criticality readiness check for object storage.
///
/// The probe consumes at most one list row below the crate-owned fixed root and exposes only the
/// stable [`ErrorCode`] on failure.
#[must_use]
pub fn object_store_health_check(store: BlobStore, timeout: Duration) -> HealthCheckSpec {
    HealthCheckSpec::new(
        HEALTH_CHECK_NAME,
        MODULE_NAME,
        Criticality::Degraded,
        timeout,
        move || {
            let store = store.clone();
            async move {
                store
                    .health_probe()
                    .await
                    .map_err(|_| CheckFailure::new(unavailable_code()))
            }
        },
    )
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static object-storage health code must be valid")
    };
    code
}
