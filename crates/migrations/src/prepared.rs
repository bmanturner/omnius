use std::{future::Future, pin::Pin};

use sqlx::migrate::{Migration, MigrationSource};

use crate::{MigrationError, Migrator};

type BoxDynError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// First version reserved for application-owned migrations.
pub const APPLICATION_MIGRATION_MINIMUM: i64 = 9_000_000_000_000_000_000;
/// Last version reserved for application-owned migrations.
pub const APPLICATION_MIGRATION_MAXIMUM: i64 = 9_099_999_999_999_999_999;

/// Optional application-owned migrations embedded by a generated service.
#[derive(Clone, Copy)]
pub struct ApplicationMigrations(Option<&'static Migrator>);

impl ApplicationMigrations {
    /// Selects framework migrations only.
    #[must_use]
    pub const fn none() -> Self {
        Self(None)
    }

    /// Selects framework migrations plus an embedded application history.
    #[must_use]
    pub const fn embedded(migrator: &'static Migrator) -> Self {
        Self(Some(migrator))
    }
}

impl std::fmt::Debug for ApplicationMigrations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ApplicationMigrations")
            .field(&if self.0.is_some() { "embedded" } else { "none" })
            .finish()
    }
}

/// A migration history prepared before any database connection is attempted.
pub enum PreparedMigrations {
    /// The unchanged framework-only history.
    Borrowed(&'static Migrator),
    /// A validated framework and application history constructed by `SQLx`.
    Owned(Migrator),
}

impl PreparedMigrations {
    /// Returns the single migrator used by every operation on a runner.
    #[must_use]
    pub fn as_migrator(&self) -> &Migrator {
        match self {
            Self::Borrowed(migrator) => migrator,
            Self::Owned(migrator) => migrator,
        }
    }
}

impl AsRef<Migrator> for PreparedMigrations {
    fn as_ref(&self) -> &Migrator {
        self.as_migrator()
    }
}

impl From<&'static Migrator> for PreparedMigrations {
    fn from(migrator: &'static Migrator) -> Self {
        Self::Borrowed(migrator)
    }
}

impl From<Migrator> for PreparedMigrations {
    fn from(migrator: Migrator) -> Self {
        Self::Owned(migrator)
    }
}

impl std::fmt::Debug for PreparedMigrations {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Borrowed(_) => "PreparedMigrations::Borrowed",
            Self::Owned(_) => "PreparedMigrations::Owned",
        })
    }
}

/// Validates and prepares one coherent framework and application history.
///
/// Framework-only preparation returns the original migrator without allocating.
/// Embedded application migrations are validated and combined through public
/// `SQLx` migration APIs before the caller can attempt a database connection.
///
/// # Errors
///
/// Returns [`MigrationError`] for down migrations, duplicate versions,
/// application versions outside the reserved range, or `SQLx` construction
/// failure.
pub async fn prepare_migrations(
    framework: &'static Migrator,
    application: ApplicationMigrations,
) -> Result<PreparedMigrations, MigrationError> {
    let Some(application) = application.0 else {
        validate_borrowed_framework(framework)?;
        return Ok(PreparedMigrations::Borrowed(framework));
    };

    let source = CombinedMigrationSource::new(framework, application)?;
    Migrator::new(source)
        .await
        .map(PreparedMigrations::Owned)
        .map_err(map_construction_error)
}

fn validate_borrowed_framework(framework: &Migrator) -> Result<(), MigrationError> {
    for (index, migration) in framework.iter().enumerate() {
        if migration.migration_type.is_down_migration() {
            return Err(MigrationError::DownMigration {
                version: migration.version,
            });
        }
        if framework
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.version == migration.version)
        {
            return Err(MigrationError::DuplicateVersion {
                version: migration.version,
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
struct CombinedMigrationSource {
    migrations: Vec<Migration>,
}

impl CombinedMigrationSource {
    fn new(framework: &Migrator, application: &Migrator) -> Result<Self, MigrationError> {
        let capacity = framework
            .iter()
            .len()
            .checked_add(application.iter().len())
            .ok_or(MigrationError::Construction)?;
        let mut migrations = Vec::with_capacity(capacity);

        Self::append(&mut migrations, framework, false)?;
        Self::append(&mut migrations, application, true)?;
        migrations.sort_unstable_by_key(|migration| migration.version);

        if let Some(version) = migrations
            .windows(2)
            .find_map(|pair| (pair[0].version == pair[1].version).then_some(pair[0].version))
        {
            return Err(MigrationError::DuplicateVersion { version });
        }

        Ok(Self { migrations })
    }

    fn append(
        migrations: &mut Vec<Migration>,
        source: &Migrator,
        application: bool,
    ) -> Result<(), MigrationError> {
        for migration in source.iter() {
            if migration.migration_type.is_down_migration() {
                return Err(MigrationError::DownMigration {
                    version: migration.version,
                });
            }
            if application
                && !(APPLICATION_MIGRATION_MINIMUM..=APPLICATION_MIGRATION_MAXIMUM)
                    .contains(&migration.version)
            {
                return Err(MigrationError::ApplicationVersionOutOfRange {
                    version: migration.version,
                });
            }
            migrations.push(migration.clone());
        }
        Ok(())
    }
}

impl MigrationSource<'static> for CombinedMigrationSource {
    fn resolve(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>> {
        Box::pin(async move { Ok(self.migrations) })
    }
}

fn map_construction_error(_: sqlx::migrate::MigrateError) -> MigrationError {
    MigrationError::Construction
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use sqlx::migrate::{MigrateError, MigrationType};

    use super::*;
    use crate::MIGRATOR;

    const FRAMEWORK_DESCRIPTION: &str = "framework";
    const FRAMEWORK_SQL: &str = "SELECT 1";
    const FRAMEWORK_CHECKSUM: &[u8] = b"framework-checksum";
    const APPLICATION_DESCRIPTION: &str = "application";
    const APPLICATION_SQL: &str = "SELECT 2";
    const APPLICATION_CHECKSUM: &[u8] = b"application-checksum";
    static APPLICATION_MIGRATOR: Migrator = sqlx::migrate!("tests/fixtures/application");

    #[derive(Debug)]
    struct TestMigrationSource(Vec<Migration>);

    impl MigrationSource<'static> for TestMigrationSource {
        fn resolve(
            self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>>
        {
            Box::pin(async move { Ok(self.0) })
        }
    }

    fn migration(
        version: i64,
        description: &'static str,
        migration_type: MigrationType,
        sql: &'static str,
        checksum: &'static [u8],
    ) -> Migration {
        Migration {
            version,
            description: Cow::Borrowed(description),
            migration_type,
            sql: Cow::Borrowed(sql),
            checksum: Cow::Borrowed(checksum),
            no_tx: false,
        }
    }

    async fn migrator(migrations: Vec<Migration>) -> Result<Migrator, MigrateError> {
        Migrator::new(TestMigrationSource(migrations)).await
    }

    #[tokio::test]
    async fn none_returns_the_framework_migrator_by_reference() -> Result<(), BoxDynError> {
        let prepared = prepare_migrations(&MIGRATOR, ApplicationMigrations::none()).await?;
        let PreparedMigrations::Borrowed(migrator) = prepared else {
            return Err("framework-only preparation allocated an owned migrator".into());
        };

        assert!(std::ptr::eq(migrator, &raw const MIGRATOR));
        Ok(())
    }

    #[tokio::test]
    async fn combined_source_sorts_and_preserves_borrowed_descriptors() -> Result<(), BoxDynError> {
        let framework = migrator(vec![migration(
            2,
            FRAMEWORK_DESCRIPTION,
            MigrationType::Simple,
            FRAMEWORK_SQL,
            FRAMEWORK_CHECKSUM,
        )])
        .await?;
        let application = migrator(vec![migration(
            APPLICATION_MIGRATION_MINIMUM,
            APPLICATION_DESCRIPTION,
            MigrationType::Simple,
            APPLICATION_SQL,
            APPLICATION_CHECKSUM,
        )])
        .await?;
        let source = CombinedMigrationSource::new(&framework, &application)?;

        assert_eq!(source.migrations.capacity(), 2);
        assert_eq!(
            source
                .migrations
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            vec![2, APPLICATION_MIGRATION_MINIMUM]
        );
        assert!(matches!(
            &source.migrations[0].description,
            Cow::Borrowed(_)
        ));
        assert_eq!(
            source.migrations[0].description.as_ref(),
            FRAMEWORK_DESCRIPTION
        );
        assert!(matches!(&source.migrations[0].sql, Cow::Borrowed(_)));
        assert_eq!(source.migrations[0].sql.as_ref(), FRAMEWORK_SQL);
        assert!(matches!(&source.migrations[0].checksum, Cow::Borrowed(_)));
        assert_eq!(source.migrations[0].checksum.as_ref(), FRAMEWORK_CHECKSUM);
        assert!(matches!(
            &source.migrations[1].description,
            Cow::Borrowed(_)
        ));
        assert_eq!(
            source.migrations[1].description.as_ref(),
            APPLICATION_DESCRIPTION
        );
        assert!(matches!(&source.migrations[1].sql, Cow::Borrowed(_)));
        assert_eq!(source.migrations[1].sql.as_ref(), APPLICATION_SQL);
        assert!(matches!(&source.migrations[1].checksum, Cow::Borrowed(_)));
        assert_eq!(source.migrations[1].checksum.as_ref(), APPLICATION_CHECKSUM);
        Ok(())
    }

    #[tokio::test]
    async fn embedded_preparation_constructs_an_owned_migrator() -> Result<(), BoxDynError> {
        let prepared = prepare_migrations(
            &MIGRATOR,
            ApplicationMigrations::embedded(&APPLICATION_MIGRATOR),
        )
        .await?;
        let PreparedMigrations::Owned(migrator) = prepared else {
            return Err("embedded preparation did not construct an owned migrator".into());
        };

        assert_eq!(
            migrator
                .iter()
                .next_back()
                .map(|migration| migration.version),
            Some(APPLICATION_MIGRATION_MINIMUM)
        );
        Ok(())
    }

    #[tokio::test]
    async fn down_migrations_are_rejected_from_both_sources() -> Result<(), BoxDynError> {
        let framework = migrator(vec![migration(
            1,
            FRAMEWORK_DESCRIPTION,
            MigrationType::ReversibleDown,
            FRAMEWORK_SQL,
            FRAMEWORK_CHECKSUM,
        )])
        .await?;
        let application = migrator(vec![migration(
            APPLICATION_MIGRATION_MINIMUM,
            APPLICATION_DESCRIPTION,
            MigrationType::Simple,
            APPLICATION_SQL,
            APPLICATION_CHECKSUM,
        )])
        .await?;
        assert!(matches!(
            CombinedMigrationSource::new(&framework, &application),
            Err(MigrationError::DownMigration { version: 1 })
        ));

        let framework = migrator(vec![migration(
            1,
            FRAMEWORK_DESCRIPTION,
            MigrationType::Simple,
            FRAMEWORK_SQL,
            FRAMEWORK_CHECKSUM,
        )])
        .await?;
        let application = migrator(vec![migration(
            APPLICATION_MIGRATION_MINIMUM,
            APPLICATION_DESCRIPTION,
            MigrationType::ReversibleDown,
            APPLICATION_SQL,
            APPLICATION_CHECKSUM,
        )])
        .await?;
        assert!(matches!(
            CombinedMigrationSource::new(&framework, &application),
            Err(MigrationError::DownMigration {
                version: APPLICATION_MIGRATION_MINIMUM
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn application_range_accepts_both_boundaries() -> Result<(), BoxDynError> {
        let framework = migrator(vec![migration(
            1,
            FRAMEWORK_DESCRIPTION,
            MigrationType::Simple,
            FRAMEWORK_SQL,
            FRAMEWORK_CHECKSUM,
        )])
        .await?;
        let application = migrator(vec![
            migration(
                APPLICATION_MIGRATION_MAXIMUM,
                APPLICATION_DESCRIPTION,
                MigrationType::Simple,
                APPLICATION_SQL,
                APPLICATION_CHECKSUM,
            ),
            migration(
                APPLICATION_MIGRATION_MINIMUM,
                APPLICATION_DESCRIPTION,
                MigrationType::Simple,
                APPLICATION_SQL,
                APPLICATION_CHECKSUM,
            ),
        ])
        .await?;
        let source = CombinedMigrationSource::new(&framework, &application)?;

        assert_eq!(
            source
                .migrations
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            vec![
                1,
                APPLICATION_MIGRATION_MINIMUM,
                APPLICATION_MIGRATION_MAXIMUM
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn application_range_rejects_both_outliers() -> Result<(), BoxDynError> {
        let framework = migrator(vec![migration(
            1,
            FRAMEWORK_DESCRIPTION,
            MigrationType::Simple,
            FRAMEWORK_SQL,
            FRAMEWORK_CHECKSUM,
        )])
        .await?;
        for version in [
            APPLICATION_MIGRATION_MINIMUM - 1,
            APPLICATION_MIGRATION_MAXIMUM + 1,
        ] {
            let application = migrator(vec![migration(
                version,
                APPLICATION_DESCRIPTION,
                MigrationType::Simple,
                APPLICATION_SQL,
                APPLICATION_CHECKSUM,
            )])
            .await?;
            assert!(matches!(
                CombinedMigrationSource::new(&framework, &application),
                Err(MigrationError::ApplicationVersionOutOfRange { version: rejected })
                    if rejected == version
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_versions_are_rejected_within_and_across_sources() -> Result<(), BoxDynError>
    {
        let application = migrator(vec![migration(
            APPLICATION_MIGRATION_MINIMUM,
            APPLICATION_DESCRIPTION,
            MigrationType::Simple,
            APPLICATION_SQL,
            APPLICATION_CHECKSUM,
        )])
        .await?;
        let duplicate_framework = migrator(vec![
            migration(
                1,
                FRAMEWORK_DESCRIPTION,
                MigrationType::Simple,
                FRAMEWORK_SQL,
                FRAMEWORK_CHECKSUM,
            ),
            migration(
                1,
                FRAMEWORK_DESCRIPTION,
                MigrationType::Simple,
                FRAMEWORK_SQL,
                FRAMEWORK_CHECKSUM,
            ),
        ])
        .await?;
        assert!(matches!(
            CombinedMigrationSource::new(&duplicate_framework, &application),
            Err(MigrationError::DuplicateVersion { version: 1 })
        ));

        let framework = migrator(vec![migration(
            APPLICATION_MIGRATION_MINIMUM,
            FRAMEWORK_DESCRIPTION,
            MigrationType::Simple,
            FRAMEWORK_SQL,
            FRAMEWORK_CHECKSUM,
        )])
        .await?;
        let duplicate_application = migrator(vec![
            migration(
                APPLICATION_MIGRATION_MINIMUM,
                APPLICATION_DESCRIPTION,
                MigrationType::Simple,
                APPLICATION_SQL,
                APPLICATION_CHECKSUM,
            ),
            migration(
                APPLICATION_MIGRATION_MINIMUM,
                APPLICATION_DESCRIPTION,
                MigrationType::Simple,
                APPLICATION_SQL,
                APPLICATION_CHECKSUM,
            ),
        ])
        .await?;
        assert!(matches!(
            CombinedMigrationSource::new(&framework, &duplicate_application),
            Err(MigrationError::DuplicateVersion {
                version: APPLICATION_MIGRATION_MINIMUM
            })
        ));

        let one_application = migrator(vec![migration(
            APPLICATION_MIGRATION_MINIMUM,
            APPLICATION_DESCRIPTION,
            MigrationType::Simple,
            APPLICATION_SQL,
            APPLICATION_CHECKSUM,
        )])
        .await?;
        assert!(matches!(
            CombinedMigrationSource::new(&framework, &one_application),
            Err(MigrationError::DuplicateVersion {
                version: APPLICATION_MIGRATION_MINIMUM
            })
        ));
        Ok(())
    }

    #[test]
    fn construction_errors_do_not_expose_sqlx_details() {
        let error =
            MigrateError::Source(Box::new(std::io::Error::other("sensitive source detail")));

        assert_eq!(map_construction_error(error), MigrationError::Construction);
    }
}
