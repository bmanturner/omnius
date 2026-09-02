//! Generated service composition and operational HTTP surface.

mod application;
mod composition;

use axum::{Router, routing::get};
use omnius_health::{HealthBuilder, HealthConfig, HealthService};
use omnius_http::{HttpShell, HttpShellConfig, StaticDelivery, StaticDeliveryConfig};
use omnius_runtime::TaskSpec;
use service_kit::{
    AppCompositionBuilder, ApplicationContributions, BuildMetadata, BuildMetadataInput,
    CompositionInput, ExampleRateLimitConfig, InvalidBuildMetadata, SchemaCompatibility,
    SelectedRuntime, WebStaticRuntime,
};

/// Fully registered service routes and supervised task specifications.
pub struct ServiceComposition {
    /// Health lifecycle shared by probes, startup, and drain coordination.
    pub health: HealthService,
    /// Router assembled by selected registrars and the HTTP shell.
    pub router: Router,
    /// Tasks assembled by selected registrars in prerequisite order.
    pub task_specs: Vec<TaskSpec>,
    /// OpenAPI fragments emitted by the same registrars that mounted operations.
    pub openapi_fragments: Vec<serde_json::Value>,
}

/// Returns the selected profile ID.
#[must_use]
pub const fn selected_profile() -> &'static str {
    composition::PROFILE
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
            schema: SchemaCompatibility {
                minimum: "none",
                maximum: "none",
            },
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
pub async fn compose(
    health_config: HealthConfig,
    http_config: HttpShellConfig,
    rate_limit: ExampleRateLimitConfig,
    selected_runtime: SelectedRuntime,
) -> Result<ServiceComposition, Box<dyn std::error::Error>> {
    const RATE_LIMIT_DISABLED: &[&str] = &["rate-limit-local"];
    let runtime_disabled = if rate_limit.enabled {
        &[][..]
    } else {
        RATE_LIMIT_DISABLED
    };
    let input = CompositionInput::generated(
        composition::PROFILE,
        composition::modules(),
        composition::providers(),
        runtime_disabled,
    );
    let example_router = Router::new().route("/example", get(application::example));
    let mut contributions = ApplicationContributions::new()
        .with_base(example_router, rate_limit)
        .with_selected_runtime(selected_runtime);
    if composition::modules().contains(&"web-static") {
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
        contributions =
            contributions.with_web_static(WebStaticRuntime::new(delivery.router()));
    }
    let mut contributions = application::contributions(contributions);
    let mut builder = AppCompositionBuilder::new(input, &mut contributions);
    builder.register_selected().await?;
    let application = builder.finish()?;
    let (mut router, health_specs, health_runtime, mut task_specs, openapi_fragments) =
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
        openapi_fragments,
    })
}

/// Builds a started in-process composition for focused handler tests.
///
/// # Errors
///
/// Returns an error when metadata, health configuration, or selected
/// composition is invalid.
pub async fn router() -> Result<Router, Box<dyn std::error::Error>> {
    let composition = compose(
        HealthConfig::default(),
        HttpShellConfig::default(),
        ExampleRateLimitConfig {
            enabled: true,
            replenish_every: std::time::Duration::from_secs(60),
            burst_size: 1,
            identity_buckets: 1_024,
        },
        SelectedRuntime::default(),
    )
    .await?;
    composition.health.mark_started();
    Ok(composition.router)
}
