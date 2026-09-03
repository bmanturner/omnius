use crate::{AppCompositionBuilder, CompositionError};

pub(crate) fn register(builder: &mut AppCompositionBuilder<'_>) -> Result<(), CompositionError> {
    builder.register_capability("migrations")
}

#[cfg(test)]
mod tests {
    use crate::migrations;

    static FACADE_MIGRATOR: migrations::Migrator = migrations::migrate!("../../migrations");

    #[test]
    fn facade_reexports_prepared_migration_api_and_hygienic_macro() {
        let _application: migrations::ApplicationMigrations =
            migrations::ApplicationMigrations::embedded(&FACADE_MIGRATOR);
        let compatibility = migrations::framework_schema_compatibility();

        assert_eq!(
            FACADE_MIGRATOR
                .iter()
                .next()
                .map(|migration| migration.version),
            compatibility.minimum.parse::<i64>().ok()
        );
    }
}
