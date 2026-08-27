//! Generated service composition and operational HTTP surface.

mod application;
mod composition;

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use service_kit::{
    BuildMetadata, BuildMetadataInput, InvalidBuildMetadata, SchemaCompatibility,
};

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
/// Returns [`InvalidBuildMetadata`] if the generated or release metadata is invalid.
pub fn router() -> Result<Router, InvalidBuildMetadata> {
    let state = OperationalState {
        metadata: build_metadata()?,
    };
    Ok(Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/version", get(version))
        .route("/example", get(application::example))
        .with_state(state))
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
