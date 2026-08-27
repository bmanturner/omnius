//! Static web delivery integration contracts.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::IntoResponse as _,
    routing::get,
};
use omnius_http::{
    BackendRouteMatch, BackendTransport, DEFAULT_ROUTE_TOPOLOGY_JSON, RouteTopology,
    SourceMapPolicy, StaticDelivery, StaticDeliveryConfig, StaticDeliveryError, StaticFallback,
};
use serde_json::json;
use tower::ServiceExt as _;

const JAVASCRIPT_PATH: &str = "assets/index-A1b2C3d4.js";
const STYLESHEET_PATH: &str = "assets/index-E5f6G7h8.css";
const JAVASCRIPT: &[u8] = b"console.log('built application');";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct BuildFixture {
    root: PathBuf,
    index: Vec<u8>,
}

impl BuildFixture {
    fn create() -> Result<Self, Box<dyn Error>> {
        Self::create_with_base("/")
    }

    fn create_with_base(base: &str) -> Result<Self, Box<dyn Error>> {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "omnius-static-delivery-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("assets"))?;
        fs::create_dir_all(root.join(".vite"))?;
        let index = format!(
            "<!doctype html><link rel=\"stylesheet\" href=\"{base}{STYLESHEET_PATH}\"><script type=\"module\" src=\"{base}{JAVASCRIPT_PATH}\"></script><div id=\"root\"></div>"
        )
        .into_bytes();
        fs::write(root.join("index.html"), &index)?;
        fs::write(root.join(JAVASCRIPT_PATH), JAVASCRIPT)?;
        fs::write(root.join(STYLESHEET_PATH), b"body{margin:0}")?;
        fs::write(root.join(format!("{JAVASCRIPT_PATH}.map")), b"{}")?;
        fs::write(root.join(format!("{JAVASCRIPT_PATH}.gz")), b"gzip-sidecar")?;
        fs::write(root.join(".env.production"), b"SECRET=not-public")?;
        fs::write(root.join("package.json"), b"{}")?;
        fs::write(root.join("source.ts"), b"export const secret = true;")?;
        fs::write(root.join("asyncapi.json"), b"{\"internal\":true}")?;
        let manifest = json!({
            "index.html": {
                "file": JAVASCRIPT_PATH,
                "isEntry": true,
                "css": [STYLESHEET_PATH]
            }
        });
        fs::write(
            root.join(".vite/manifest.json"),
            serde_json::to_vec(&manifest)?,
        )?;
        Ok(Self { root, index })
    }

    fn config(&self) -> StaticDeliveryConfig {
        StaticDeliveryConfig {
            asset_dir: self.root.clone(),
            ..StaticDeliveryConfig::default()
        }
    }

    fn remove(&self, relative: &str) -> Result<(), Box<dyn Error>> {
        fs::remove_file(self.root.join(relative))?;
        Ok(())
    }
}

impl Drop for BuildFixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

async fn request(
    app: Router,
    method: Method,
    uri: &str,
    headers: &[(&'static str, &'static str)],
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    Ok(app.oneshot(builder.body(Body::empty())?).await?)
}

async fn response_body(response: axum::response::Response) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

#[tokio::test]
async fn fingerprinted_asset_has_mime_etag_and_immutable_cache() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    let response = request(
        delivery.router(),
        Method::GET,
        &format!("/{JAVASCRIPT_PATH}"),
        &[],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static(
            "public, max-age=31536000, immutable"
        ))
    );
    assert!(response.headers().contains_key(header::ETAG));
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/javascript")
    );
    assert_eq!(response_body(response).await?, JAVASCRIPT);
    Ok(())
}

#[tokio::test]
async fn head_returns_asset_headers_without_a_body() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    let response = request(
        delivery.router(),
        Method::HEAD,
        &format!("/{JAVASCRIPT_PATH}"),
        &[],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&header::HeaderValue::from_static("33"))
    );
    assert!(response_body(response).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn byte_range_is_delegated_to_tower_http() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    let response = request(
        delivery.router(),
        Method::GET,
        &format!("/{JAVASCRIPT_PATH}"),
        &[("range", "bytes=0-7")],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response_body(response).await?, b"console.");
    Ok(())
}

#[tokio::test]
async fn application_shell_and_deep_links_are_not_cached() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    let response = request(delivery.router(), Method::GET, "/records/42", &[]).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-cache"))
    );
    assert_eq!(response_body(response).await?, fixture.index);
    Ok(())
}

#[tokio::test]
async fn missing_asset_paths_are_real_not_found_responses() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    for uri in ["/assets/missing.js", "/assets/extensionless"] {
        let response = request(delivery.router(), Method::GET, uri, &[]).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "uri={uri}");
        assert!(response_body(response).await?.is_empty(), "uri={uri}");
    }
    Ok(())
}

#[tokio::test]
async fn explicit_not_found_mode_disables_spa_fallback() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.fallback = StaticFallback::NotFound;
    let delivery = StaticDelivery::new(config)?;

    let response = request(delivery.router(), Method::GET, "/records/42", &[]).await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn backend_routes_and_backend_not_found_responses_are_preserved() -> Result<(), Box<dyn Error>>
{
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;
    let backend = Router::new()
        .route(
            "/api/known",
            get(|| async { (StatusCode::NOT_FOUND, "backend-not-found").into_response() }),
        )
        .merge(delivery.router());

    let matched = request(backend.clone(), Method::GET, "/api/known", &[]).await?;
    let reserved = request(backend, Method::GET, "/api/missing", &[]).await?;

    assert_eq!(matched.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_body(matched).await?, b"backend-not-found");
    assert_eq!(reserved.status(), StatusCode::NOT_FOUND);
    assert!(response_body(reserved).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn traversal_and_sensitive_build_files_are_denied() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    for uri in [
        "/assets/%2e%2e/index.html",
        "/.env.production",
        "/package.json",
        "/contracts/openapi.json",
        "/source.ts",
        "/asyncapi.json",
    ] {
        let response = request(delivery.router(), Method::GET, uri, &[]).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "uri={uri}");
        assert!(response_body(response).await?.is_empty(), "uri={uri}");
    }
    Ok(())
}

#[tokio::test]
async fn source_maps_are_denied_by_default() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    let response = request(
        delivery.router(),
        Method::GET,
        &format!("/{JAVASCRIPT_PATH}.map"),
        &[],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn source_maps_can_be_explicitly_served() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.source_maps = SourceMapPolicy::Public;
    let delivery = StaticDelivery::new(config)?;

    let response = request(
        delivery.router(),
        Method::GET,
        &format!("/{JAVASCRIPT_PATH}.map"),
        &[],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await?, b"{}");
    Ok(())
}

#[test]
fn missing_build_fails_with_a_redacted_typed_error() {
    let config = StaticDeliveryConfig {
        asset_dir: PathBuf::from("/definitely/not/a/real/omnius-build"),
        ..StaticDeliveryConfig::default()
    };

    let error = StaticDelivery::new(config).err();

    assert_eq!(error, Some(StaticDeliveryError::AssetDirectoryUnavailable));
    assert!(
        error
            .as_ref()
            .is_some_and(|error| !error.to_string().contains("/definitely"))
    );
}

#[test]
fn missing_manifest_asset_fails_before_router_assembly() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    fixture.remove(JAVASCRIPT_PATH)?;

    assert_eq!(
        StaticDelivery::new(fixture.config()).err(),
        Some(StaticDeliveryError::ReferencedAssetUnavailable)
    );
    Ok(())
}

#[test]
fn readiness_fails_after_a_required_asset_disappears() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;
    fixture.remove(JAVASCRIPT_PATH)?;

    assert!(delivery.check_readiness().is_err());
    Ok(())
}

#[test]
fn readiness_fails_when_the_application_shell_becomes_empty() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;
    fs::write(fixture.root.join("index.html"), b"")?;

    assert!(delivery.check_readiness().is_err());
    Ok(())
}

#[tokio::test]
async fn explicit_base_path_is_required_and_serves_deep_links() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create_with_base("/console/")?;
    let mut config = fixture.config();
    config.base_path = "/console/".to_owned();
    let delivery = StaticDelivery::new(config)?;

    let outside = request(delivery.router(), Method::GET, "/records/42", &[]).await?;
    let inside = request(delivery.router(), Method::GET, "/console/records/42", &[]).await?;

    assert_eq!(delivery.base_path(), "/console");
    assert_eq!(outside.status(), StatusCode::NOT_FOUND);
    assert_eq!(inside.status(), StatusCode::OK);
    assert_eq!(response_body(inside).await?, fixture.index);
    Ok(())
}

#[tokio::test]
async fn explicit_base_path_is_preserved_in_directory_redirects() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create_with_base("/console/")?;
    let mut config = fixture.config();
    config.base_path = "/console".to_owned();
    let delivery = StaticDelivery::new(config)?;

    let response = request(delivery.router(), Method::GET, "/console/assets", &[]).await?;

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&header::HeaderValue::from_static("/console/assets/"))
    );
    Ok(())
}

#[test]
fn build_base_path_must_match_runtime_base_path() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.base_path = "/console".to_owned();

    assert_eq!(
        StaticDelivery::new(config).err(),
        Some(StaticDeliveryError::IndexBasePathMismatch)
    );
    Ok(())
}

#[tokio::test]
async fn precompressed_sidecar_is_negotiated_without_double_encoding() -> Result<(), Box<dyn Error>>
{
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    let response = request(
        delivery.router(),
        Method::GET,
        &format!("/{JAVASCRIPT_PATH}"),
        &[("accept-encoding", "gzip")],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_ENCODING),
        Some(&header::HeaderValue::from_static("gzip"))
    );
    assert_eq!(response_body(response).await?, b"gzip-sidecar");
    Ok(())
}

#[test]
fn shared_route_topology_reserves_normative_http_ws_and_sse_paths() -> Result<(), Box<dyn Error>> {
    let topology = RouteTopology::from_json(DEFAULT_ROUTE_TOPOLOGY_JSON)?;

    for path in [
        "/api/unknown",
        "/reference-records/missing",
        "/realtime/ws/channel",
        "/ws/channel",
        "/events/stream",
        "/live/missing",
        "/docs/missing",
        "/metrics/missing",
        "/_health/dependency",
        "/_metrics/missing",
    ] {
        assert!(topology.is_reserved(path), "path={path}");
    }
    assert!(topology.routes().iter().any(|route| {
        route.path() == "/realtime/ws"
            && route.route_match() == BackendRouteMatch::Prefix
            && route.transport() == BackendTransport::Websocket
    }));
    assert!(
        topology.routes().iter().any(|route| {
            route.path() == "/events" && route.transport() == BackendTransport::Sse
        })
    );
    Ok(())
}

#[test]
fn unknown_static_configuration_keys_are_rejected() {
    let result = serde_json::from_value::<StaticDeliveryConfig>(json!({
        "asset_dir": "web/dist",
        "unexpected": true
    }));

    assert!(result.is_err());
}

#[test]
fn unsafe_base_path_is_rejected_without_touching_the_filesystem() {
    let config = StaticDeliveryConfig {
        asset_dir: PathBuf::from("unused"),
        base_path: "/console/../admin".to_owned(),
        ..StaticDeliveryConfig::default()
    };

    assert_eq!(
        config.validate().err(),
        Some(StaticDeliveryError::InvalidBasePath)
    );
}

#[cfg(unix)]
#[test]
fn symlinked_build_content_is_rejected() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let fixture = BuildFixture::create()?;
    symlink(Path::new("index.html"), fixture.root.join("unsafe-link"))?;

    assert_eq!(
        StaticDelivery::new(fixture.config()).err(),
        Some(StaticDeliveryError::UnsafeAssetTree)
    );
    Ok(())
}
