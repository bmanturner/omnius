use std::{error::Error, net::SocketAddr};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

type TestResult = Result<(), Box<dyn Error>>;

#[tokio::test]
async fn selected_profile_is_operational_or_fails_closed_without_runtime_inputs() -> TestResult {
    if service::requires_runtime_inputs() {
        let error = match service::router().await {
            Ok(_) => return Err("profile composed without its selected runtime inputs".into()),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("requires application contribution")
        );
        return Ok(());
    }

    let app = service::router().await?;
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
    assert_eq!(metadata["profile"], "{{ profile }}");
    assert_eq!(metadata["modules"].as_array().map(Vec::len), Some(9));
    assert!(
        metadata["providers"]
            .as_array()
            .is_some_and(|providers| !providers.is_empty())
    );

    let first = app.clone().oneshot(example_request()?).await?;
    assert_eq!(first.status(), StatusCode::OK);
    let body = first.into_body().collect().await?.to_bytes();
    let example: Value = serde_json::from_slice(&body)?;
    assert_eq!(example["message"], "hello from {{project-name}}");

    let limited = app.oneshot(example_request()?).await?;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

fn example_request() -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::get("/example").body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 30_000))));
    Ok(request)
}
