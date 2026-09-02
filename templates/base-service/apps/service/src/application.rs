use axum::Json;
use serde::Serialize;

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

#[derive(Serialize)]
pub(crate) struct ExampleResponse {
    message: &'static str,
}

pub(crate) async fn example() -> Json<ExampleResponse> {
    Json(ExampleResponse {
        message: "hello from {{project-name}}",
    })
}
