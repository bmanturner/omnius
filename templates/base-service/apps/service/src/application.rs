use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct ExampleResponse {
    message: &'static str,
}

pub(crate) async fn example() -> Json<ExampleResponse> {
    Json(ExampleResponse {
        message: "hello from {{project-name}}",
    })
}
