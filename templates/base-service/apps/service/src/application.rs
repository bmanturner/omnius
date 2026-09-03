use axum::Router;
use serde_json::json;
use service_kit::ApplicationExtension;

/// Application-owned contribution boundary.
///
/// The generated root deliberately supplies no advanced policy port. Profile
/// verification may replace this boundary with behavior-bearing test doubles;
/// untouched roots therefore fail closed when a selected module declares an
/// application requirement.
pub(crate) fn contributions(
    contributions: service_kit::ApplicationContributions,
) -> service_kit::ApplicationContributions {
    contributions
}

pub(crate) fn default_extension() -> ApplicationExtension {
    ApplicationExtension::new(
        Router::new(),
        &[],
        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "{{project-name}}",
                "version": env!("CARGO_PKG_VERSION")
            },
            "paths": {}
        }),
        &[],
    )
}
