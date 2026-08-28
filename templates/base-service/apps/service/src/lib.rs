//! Generated service composition and operational HTTP surface.

mod application;
mod composition;

use axum::{Json, Router, extract::State, routing::get};
use omnius_http::{StaticDelivery, StaticDeliveryConfig};
use serde::Serialize;
use service_kit::{BuildMetadata, BuildMetadataInput, InvalidBuildMetadata, SchemaCompatibility};

#[derive(Clone, Copy)]
struct OperationalState {
    metadata: BuildMetadata,
}

#[derive(Serialize)]
struct ProbeBody {
    status: &'static str,
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

/// Builds the public service router with operational and example routes.
///
/// # Errors
///
/// Returns an error if generated metadata is invalid or the selected static web build cannot be
/// validated.
pub fn router() -> Result<Router, Box<dyn std::error::Error>> {
    let state = OperationalState {
        metadata: build_metadata()?,
    };
    let router = Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/version", get(version))
        .route("/example", get(application::example))
        .with_state(state);
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
        Ok(router.merge(delivery.router()))
    } else {
        Ok(router)
    }
}

async fn live() -> Json<ProbeBody> {
    Json(ProbeBody { status: "live" })
}

async fn ready() -> Json<ProbeBody> {
    Json(ProbeBody { status: "ready" })
}

async fn startup() -> Json<ProbeBody> {
    Json(ProbeBody { status: "started" })
}

async fn version(State(state): State<OperationalState>) -> Json<BuildMetadata> {
    Json(state.metadata)
}
