use std::error::Error;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

type TestResult = Result<(), Box<dyn Error>>;

#[tokio::test]
async fn selected_profile_is_operational_or_fails_closed_without_runtime_inputs() -> TestResult {
    if service::requires_runtime_inputs() {
        if service::router().is_ok() {
            return Err("profile composed without its selected runtime inputs".into());
        }
        return Ok(());
    }

    let app = service::router()?;
    for path in ["/live", "/ready", "/startup"] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }

    let response = app
        .clone()
        .oneshot(Request::get("/version").body(Body::empty())?)
        .await?;
    let body = response.into_body().collect().await?.to_bytes();
    let metadata: Value = serde_json::from_slice(&body)?;
    assert_eq!(metadata["profile"], "api");
    assert_eq!(
        metadata["modules"],
        serde_json::to_value(service::selected_modules())?
    );

    if !service::selected_modules().contains(&"web-static") {
        for path in ["/example", "/reference-records"] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
    Ok(())
}
