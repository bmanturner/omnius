use std::error::Error;

use axum::{body::Body, http::{Request, StatusCode}};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

type TestResult = Result<(), Box<dyn Error>>;

#[tokio::test]
async fn operational_endpoints_are_ready_and_expose_resolved_profile() -> TestResult {
    let app = service::router()?;
    for path in ["/live", "/ready", "/startup"] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }

    let response = app
        .oneshot(Request::get("/version").body(Body::empty())?)
        .await?;
    let body = response.into_body().collect().await?.to_bytes();
    let metadata: Value = serde_json::from_slice(&body)?;
    assert_eq!(metadata["profile"], "{{ profile }}");
    assert!(metadata["modules"].as_array().is_some_and(|modules| !modules.is_empty()));
    assert!(
        metadata["providers"]
            .as_array()
            .is_some_and(|providers| !providers.is_empty())
    );
    Ok(())
}

#[tokio::test]
async fn application_example_is_mounted() -> TestResult {
    let response = service::router()?
        .oneshot(Request::get("/example").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    let example: Value = serde_json::from_slice(&body)?;
    assert_eq!(example["message"], "hello from {{project-name}}");
    Ok(())
}
