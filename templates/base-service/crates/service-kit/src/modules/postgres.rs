use crate::{AppCompositionBuilder, CompositionError};

pub(crate) async fn register(
    builder: &mut AppCompositionBuilder<'_>,
) -> Result<(), CompositionError> {
    builder.register_capability("postgres")?;
    let health = builder.postgres_pool("postgres")?.health_check();
    builder.register_health("postgres-connectivity", health)
}
