use crate::{AppCompositionBuilder, CompositionError};

pub(crate) fn register(builder: &mut AppCompositionBuilder<'_>) -> Result<(), CompositionError> {
    builder.register_capability("http")
}

pub(crate) fn finalize(builder: &mut AppCompositionBuilder<'_>) -> Result<(), CompositionError> {
    let extension = builder.take_application_extension()?;
    let crate::ApplicationExtension {
        router,
        routes,
        openapi_document,
        operations,
    } = extension;
    for operation in operations {
        builder.register_public_operation(operation.operation_id)?;
    }
    #[cfg(feature = "rate-limit-local")]
    let router = match builder.take_application_rate_limiter() {
        Some(limiter) => crate::modules::rate_limit_local::apply(router, &limiter),
        None => router,
    };
    builder.register_router(router, routes)?;
    #[cfg(feature = "openapi")]
    builder.install_openapi_catalog(openapi_document, operations)?;
    #[cfg(not(feature = "openapi"))]
    drop(openapi_document);
    Ok(())
}
