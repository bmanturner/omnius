//! Public runtime metadata endpoint and contract-hash consistency.

use std::{collections::BTreeSet, error::Error};

use axum::{
    body::to_bytes,
    http::{Request, header},
};
use omnius_api_server::{
    PUBLIC_API_VERSION, PUBLIC_PROFILE, aggregate_contract_sha256, metadata_router,
};
use serde_json::Value;
use tower::ServiceExt as _;

#[tokio::test]
async fn metadata_route_returns_only_the_public_compatibility_shape() -> Result<(), Box<dyn Error>>
{
    let response = metadata_router()
        .oneshot(Request::get("/api/_meta").body(axum::body::Body::empty())?)
        .await?;
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    let fields = body
        .as_object()
        .ok_or("runtime metadata response was not an object")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_fields = BTreeSet::from([
        "api_version",
        "application_version",
        "build_revision",
        "capabilities",
        "contract_hash",
        "profile",
        "transports",
    ]);

    assert_eq!(
        (
            status.as_u16(),
            fields,
            body.get("api_version"),
            body.get("profile"),
            body.get("capabilities"),
            body.get("transports"),
        ),
        (
            200,
            expected_fields,
            Some(&Value::String(PUBLIC_API_VERSION.to_owned())),
            Some(&Value::String(PUBLIC_PROFILE.to_owned())),
            Some(&serde_json::json!([
                "web-auth",
                "web-realtime",
                "web-uploads"
            ])),
            Some(&serde_json::json!({
                "api": "/api",
                "sse": "/events",
                "websocket": "/realtime/ws"
            })),
        )
    );
    Ok(())
}

#[tokio::test]
async fn metadata_route_is_never_stored_by_browser_caches() -> Result<(), Box<dyn Error>> {
    let response = metadata_router()
        .oneshot(Request::get("/api/_meta").body(axum::body::Body::empty())?)
        .await?;

    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    Ok(())
}

#[tokio::test]
async fn metadata_hash_matches_canonical_leaf_contracts_and_derived_artifacts()
-> Result<(), Box<dyn Error>> {
    let openapi = include_bytes!("../../../contracts/openapi.json");
    let asyncapi = include_bytes!("../../../contracts/asyncapi.json");
    let permissions = include_bytes!("../../../contracts/permissions.json");
    let aggregate = aggregate_contract_sha256(openapi, asyncapi, permissions);
    let response = metadata_router()
        .oneshot(Request::get("/api/_meta").body(axum::body::Body::empty())?)
        .await?;
    let metadata: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    let capabilities: Value =
        serde_json::from_slice(include_bytes!("../../../contracts/capabilities.json"))?;
    let manifest: Value =
        serde_json::from_slice(include_bytes!("../../../contracts/contract-manifest.json"))?;
    let expected = format!("sha256:{aggregate}");

    assert_eq!(
        (
            metadata.get("contract_hash").and_then(Value::as_str),
            capabilities.get("contract_hash").and_then(Value::as_str),
            manifest.get("aggregate_sha256").and_then(Value::as_str),
        ),
        (
            Some(expected.as_str()),
            Some(expected.as_str()),
            Some(aggregate.as_str())
        )
    );
    Ok(())
}
