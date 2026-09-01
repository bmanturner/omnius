use std::sync::Arc;

use omnius_core::SystemClock;
use omnius_reference_api::{REFERENCE_HTTP_OPERATIONS, ReferenceApiInput, build_reference_api};

use crate::{AppCompositionBuilder, CompositionError};

const ROUTES: &[&str] = &["/reference-records", "/reference-records/{id}"];

pub(crate) async fn register(
    builder: &mut AppCompositionBuilder<'_>,
) -> Result<(), CompositionError> {
    builder.register_capability("idempotency")?;
    if builder.module_selected("auth-core") {
        return Ok(());
    }
    let runtime = builder.api_runtime("idempotency")?;
    let api = build_reference_api(ReferenceApiInput {
        pool: runtime.pool.clone(),
        cursor_codec: runtime.cursor_codec.clone(),
        idempotency_store: runtime.idempotency_store()?,
        clock: Arc::new(SystemClock),
    })
    .map_err(|error| CompositionError::construction("idempotency", error))?;
    let parts = api.into_parts();
    builder.register_router(parts.routes, ROUTES)?;
    for operation in REFERENCE_HTTP_OPERATIONS {
        builder.register_public_operation(operation.operation_id)?;
    }
    builder.register_openapi(parts.openapi)?;
    Ok(())
}
