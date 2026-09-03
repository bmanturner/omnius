use crate::{AppCompositionBuilder, CompositionError};

// Route and task IDs are reserved by the registrar; the generated root
// materializes them after all dependency health checks are known.

pub(crate) fn register(builder: &mut AppCompositionBuilder<'_>) -> Result<(), CompositionError> {
    builder.register_capability("health")?;
    builder.register_health_runtime()
}
