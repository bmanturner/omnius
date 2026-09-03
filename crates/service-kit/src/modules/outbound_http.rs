use crate::{AppCompositionBuilder, CompositionError};

pub(crate) fn register(builder: &mut AppCompositionBuilder<'_>) -> Result<(), CompositionError> {
    builder.register_outbound_http()
}
