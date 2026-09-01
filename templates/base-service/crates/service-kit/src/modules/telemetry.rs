use crate::{AppCompositionBuilder, CompositionError};

pub(crate) async fn register(
    builder: &mut AppCompositionBuilder<'_>,
) -> Result<(), CompositionError> {
    builder.register_capability("telemetry")
}
