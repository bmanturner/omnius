//! Generated service composition and operational HTTP surface.

mod application;
mod composition;

use axum::Router;
use service_kit::{
    AppCompositionBuilder, ApplicationContributions, ApplicationRateLimitConfig, BuildMetadata,
    BuildMetadataInput, CompositionInput, InvalidBuildMetadata, SchemaCompatibility,
    SelectedRuntime,
    health::{HealthBuilder, HealthConfig, HealthService},
    http::{HttpShell, HttpShellConfig},
    runtime::TaskSpec,
};
#[cfg(selected_web_static)]
use service_kit::{
    WebStaticRuntime,
    http::{StaticDelivery, StaticDeliveryConfig},
};
#[cfg(all(selected_migrations, application_migrations))]
static APPLICATION_MIGRATOR: service_kit::migrations::Migrator =
    service_kit::migrations::migrate!("../../migrations");

/// Returns the application-owned migration source selected for this build.
#[cfg(selected_migrations)]
#[must_use]
pub const fn application_migrations() -> service_kit::migrations::ApplicationMigrations {
    #[cfg(application_migrations)]
    {
        service_kit::migrations::ApplicationMigrations::embedded(&APPLICATION_MIGRATOR)
    }
    #[cfg(not(application_migrations))]
    {
        service_kit::migrations::ApplicationMigrations::none()
    }
}

/// Prepares the exact framework-plus-application migration set before database I/O.
///
/// # Errors
///
/// Returns a migration validation or `SQLx` construction error before a connection is attempted.
#[cfg(selected_migrations)]
pub async fn prepared_migrations()
-> Result<service_kit::migrations::PreparedMigrations, service_kit::migrations::MigrationError> {
    service_kit::migrations::prepare_migrations(
        &service_kit::migrations::MIGRATOR,
        application_migrations(),
    )
    .await
}

/// Fully registered service routes and supervised task specifications.
pub struct ServiceComposition {
    /// Health lifecycle shared by probes, startup, and drain coordination.
    pub health: HealthService,
    /// Router assembled by selected registrars and the HTTP shell.
    pub router: Router,
    /// Tasks assembled by selected registrars in prerequisite order.
    pub task_specs: Vec<TaskSpec>,
}

/// Returns the selected profile ID.
#[must_use]
pub const fn selected_profile() -> &'static str {
    composition::PROFILE
}

/// Returns the database schema versions accepted by this generated application.
#[must_use]
pub const fn schema_compatibility() -> SchemaCompatibility {
    #[cfg(all(selected_migrations, application_migrations))]
    let compatibility = SchemaCompatibility {
        minimum: env!("OMNIUS_APPLICATION_SCHEMA_MINIMUM"),
        maximum: env!("OMNIUS_APPLICATION_SCHEMA_MAXIMUM"),
    };
    #[cfg(all(selected_migrations, not(application_migrations)))]
    let compatibility = service_kit::migrations::framework_schema_compatibility();
    #[cfg(not(selected_migrations))]
    let compatibility = SchemaCompatibility {
        minimum: "none",
        maximum: "none",
    };
    compatibility
}

/// Returns selected catalog module IDs in dependency order.
#[must_use]
pub fn selected_modules() -> &'static [&'static str] {
    composition::modules()
}

/// Returns whether the in-process default router lacks selected runtime inputs.
///
/// Persisted profiles require a connected [`SelectedRuntime`]; advanced
/// profiles additionally require their declared application contributions.
#[must_use]
pub fn requires_runtime_inputs() -> bool {
    composition::modules().contains(&"postgres")
        || composition::modules().contains(&"outbound-http")
        || service_kit::selected_requires_application_contributions()
}

/// Constructs validated metadata from generated service state and build inputs.
///
/// # Errors
///
/// Returns [`InvalidBuildMetadata`] when a release environment value is unsafe.
pub fn build_metadata() -> Result<BuildMetadata, InvalidBuildMetadata> {
    BuildMetadata::new(
        BuildMetadataInput {
            service: composition::SERVICE,
            profile: composition::PROFILE,
            modules: composition::modules(),
            providers: composition::providers(),
            schema: schema_compatibility(),
        },
        env!("CARGO_PKG_VERSION"),
        option_env!("OMNIUS_GIT_REVISION"),
        option_env!("OMNIUS_BUILD_TIME"),
        env!("OMNIUS_RUSTC_VERSION"),
        composition::KIT_VERSION,
    )
}

/// Builds selected registrars using lifecycle-backed health state.
///
/// # Errors
///
/// Returns an error if a selected registrar, the HTTP shell, or the selected
/// static web build cannot be constructed exactly.
pub fn compose(
    health_config: HealthConfig,
    http_config: HttpShellConfig,
    application_rate_limit: ApplicationRateLimitConfig,
    selected_runtime: SelectedRuntime,
) -> Result<ServiceComposition, Box<dyn std::error::Error>> {
    let runtime_disabled = composition::runtime_disabled_modules(application_rate_limit.enabled);
    let input = CompositionInput::generated(
        composition::PROFILE,
        composition::modules(),
        composition::providers(),
        runtime_disabled,
    );
    let contributions = ApplicationContributions::new()
        .with_application_rate_limit(application_rate_limit)
        .with_application_extension(|_| Ok(application::default_extension()));
    #[cfg(selected_web_static)]
    let contributions = {
        let mut config = StaticDeliveryConfig::default();
        if let Some(asset_dir) = std::env::var_os("OMNIUS_WEB_ASSET_DIR") {
            config.asset_dir = asset_dir.into();
        }
        if let Some(base_path) = std::env::var_os("OMNIUS_WEB_BASE_PATH") {
            config.base_path = base_path.into_string().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "OMNIUS_WEB_BASE_PATH must be valid UTF-8",
                )
            })?;
        }
        let delivery = StaticDelivery::new(config)?;
        contributions.with_web_static(WebStaticRuntime::new(delivery.router()))
    };
    let mut contributions =
        application::contributions(contributions).with_selected_runtime(selected_runtime)?;
    let mut builder = AppCompositionBuilder::new(input, &mut contributions);
    builder.register_selected()?;
    let application = builder.finish()?;
    let (mut router, health_specs, health_runtime, mut task_specs) =
        application.into_runtime_parts();
    let mut health_builder = HealthBuilder::new(build_metadata()?, health_config)?;
    for spec in health_specs {
        health_builder.register(spec)?;
    }
    let health = health_builder.build();
    if health_runtime {
        router = router.merge(health.public_router());
        task_specs.push(health.supervised_refresh_task());
    }
    let shell = HttpShell::new(http_config)?;
    let router = shell.apply(router)?;
    Ok(ServiceComposition {
        health,
        router,
        task_specs,
    })
}

/// Builds a started in-process composition for focused handler tests.
///
/// # Errors
///
/// Returns an error when metadata, health configuration, or selected
/// composition is invalid.
pub fn router() -> Result<Router, Box<dyn std::error::Error>> {
    let composition = compose(
        HealthConfig::default(),
        HttpShellConfig::default(),
        ApplicationRateLimitConfig {
            enabled: true,
            replenish_every: std::time::Duration::from_secs(60),
            burst_size: 1,
            identity_buckets: 1_024,
        },
        SelectedRuntime::default(),
    )?;
    composition.health.mark_started();
    Ok(composition.router)
}
