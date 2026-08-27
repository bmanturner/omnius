//! Static web delivery integration contracts.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::IntoResponse as _,
    routing::get,
};
use omnius_http::{
    BackendRouteMatch, BackendTransport, CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy,
    CspSource, DEFAULT_ROUTE_TOPOLOGY_JSON, RouteTopology, SourceMapPolicy, StaticAssetClass,
    StaticCacheClass, StaticContractMismatch, StaticDelivery, StaticDeliveryConfig,
    StaticDeliveryError, StaticDeliveryObserver, StaticFallback, StaticResponseObservation,
    StaticResponseStatus, TlsBoundary, WebSecurityPolicyError,
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

    fn write_source_map(&self) -> Result<(), Box<dyn Error>> {
        fs::write(self.root.join(format!("{JAVASCRIPT_PATH}.map")), b"{}")?;
        Ok(())
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
#[derive(Default)]
struct RecordingObserver {
    responses: Mutex<Vec<StaticResponseObservation>>,
    readiness: Mutex<Vec<bool>>,
    contract_mismatches: Mutex<Vec<StaticContractMismatch>>,
}

impl RecordingObserver {
    fn responses(&self) -> Vec<StaticResponseObservation> {
        self.responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn readiness(&self) -> Vec<bool> {
        self.readiness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn contract_mismatches(&self) -> Vec<StaticContractMismatch> {
        self.contract_mismatches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl StaticDeliveryObserver for RecordingObserver {
    fn observe_response(&self, observation: StaticResponseObservation) {
        self.responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(observation);
    }

    fn observe_readiness(&self, available: bool) {
        self.readiness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(available);
    }

    fn observe_contract_mismatch(&self, mismatch: StaticContractMismatch) {
        self.contract_mismatches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(mismatch);
    }
}
fn assert_default_production_security_headers(response: &axum::response::Response) {
    let csp = response
        .headers()
        .get("content-security-policy")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    for directive in [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ] {
        assert!(csp.contains(directive), "directive={directive}");
    }
    for forbidden in ["'unsafe-eval'", "'unsafe-inline'", "'nonce-", "'sha256-"] {
        assert!(!csp.contains(forbidden), "forbidden={forbidden}");
    }
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get("referrer-policy")
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );
    let permissions = response
        .headers()
        .get("permissions-policy")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(permissions.contains("camera=()"));
    assert!(permissions.contains("microphone=()"));
    assert!(permissions.contains("publickey-credentials-get=(self)"));
    assert_eq!(
        response
            .headers()
            .get("cross-origin-opener-policy")
            .and_then(|value| value.to_str().ok()),
        Some("same-origin-allow-popups")
    );
    assert_eq!(
        response
            .headers()
            .get("cross-origin-resource-policy")
            .and_then(|value| value.to_str().ok()),
        Some("same-origin")
    );
    assert!(!response.headers().contains_key("cross-origin-embedder-policy"));
    assert!(!response.headers().contains_key("strict-transport-security"));
}



#[tokio::test]
async fn production_security_headers_cover_assets_shell_and_static_errors(
) -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let delivery = StaticDelivery::new(fixture.config())?;

    for (uri, status, cache) in [
        (
            format!("/{JAVASCRIPT_PATH}"),
            StatusCode::OK,
            Some("public, max-age=31536000, immutable"),
        ),
        (
            "/records/42".to_owned(),
            StatusCode::OK,
            Some("no-cache"),
        ),
        (
            "/assets/missing.js".to_owned(),
            StatusCode::NOT_FOUND,
            None,
        ),
    ] {
        let response = request(delivery.router(), Method::GET, &uri, &[]).await?;
        assert_eq!(response.status(), status, "uri={uri}");
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            cache,
            "uri={uri}"
        );
        assert_default_production_security_headers(&response);
    }
    Ok(())
}

#[tokio::test]
async fn hsts_is_emitted_only_for_an_explicit_trusted_tls_boundary(
) -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.security.hsts.boundary = TlsBoundary::Trusted;
    config.security.hsts.max_age_seconds = 31_536_000;
    config.security.hsts.include_subdomains = true;
    let delivery = StaticDelivery::new(config)?;

    let response = request(delivery.router(), Method::GET, "/", &[]).await?;

    assert_eq!(
        response
            .headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
    Ok(())
}

#[test]
fn hsts_rejects_untrusted_boundary_options() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.security.hsts.include_subdomains = true;

    assert_eq!(
        StaticDelivery::new(config).err(),
        Some(StaticDeliveryError::SecurityPolicy(
            WebSecurityPolicyError::InvalidHsts
        ))
    );
    Ok(())
}

#[test]
fn production_csp_rejects_eval_inline_nonce_and_hash_sources() {
    for source in [
        "'unsafe-eval'",
        "'unsafe-inline'",
        "'nonce-reviewed-at-runtime'",
        "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
    ] {
        assert_eq!(
            CspSource::try_from(source),
            Err(WebSecurityPolicyError::InvalidCspSource),
            "source={source}"
        );
    }
}
#[test]
fn development_hmr_csp_cannot_be_deserialized_as_production_policy() {
    let result = serde_json::from_value::<StaticDeliveryConfig>(json!({
        "security": {
            "content_security_policy": {
                "script_src": ["'self'", "'unsafe-eval'"]
            }
        }
    }));

    assert!(result.is_err());
}
#[test]
fn inline_shell_content_is_rejected_as_a_security_contract_mismatch(
) -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut index = fixture.index.clone();
    index.extend_from_slice(b"<script>window.inline = true;</script>");
    fs::write(fixture.root.join("index.html"), index)?;
    let observer = Arc::new(RecordingObserver::default());

    assert_eq!(
        StaticDelivery::with_observer(fixture.config(), observer.clone()).err(),
        Some(StaticDeliveryError::IndexContainsInlineContent)
    );
    assert_eq!(
        observer.contract_mismatches(),
        vec![StaticContractMismatch::SecurityPolicy]
    );
    Ok(())
}



#[test]
fn cross_origin_embedder_policy_requires_same_origin_opener() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.security.cross_origin.embedder = CrossOriginEmbedderPolicy::RequireCorp;
    config.security.cross_origin.opener = CrossOriginOpenerPolicy::SameOriginAllowPopups;

    assert_eq!(
        StaticDelivery::new(config).err(),
        Some(StaticDeliveryError::SecurityPolicy(
            WebSecurityPolicyError::IncompatibleCrossOriginIsolation
        ))
    );
    Ok(())
}
#[tokio::test]
async fn compatible_cross_origin_embedder_policy_is_explicitly_applied(
) -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.security.cross_origin.embedder = CrossOriginEmbedderPolicy::RequireCorp;
    config.security.cross_origin.opener = CrossOriginOpenerPolicy::SameOrigin;
    let delivery = StaticDelivery::new(config)?;

    let response = request(delivery.router(), Method::GET, "/", &[]).await?;

    assert_eq!(
        response
            .headers()
            .get("cross-origin-embedder-policy")
            .and_then(|value| value.to_str().ok()),
        Some("require-corp")
    );
    Ok(())
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
async fn static_observations_are_normalized_and_path_independent() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let observer = Arc::new(RecordingObserver::default());
    let delivery = StaticDelivery::with_observer(fixture.config(), observer.clone())?;

    let _asset_response = request(
        delivery.router(),
        Method::GET,
        &format!("/{JAVASCRIPT_PATH}"),
        &[],
    )
    .await?;
    let _fallback_response =
        request(delivery.router(), Method::GET, "/records/42", &[]).await?;
    let _first_missing_response = request(
        delivery.router(),
        Method::GET,
        "/assets/customer-12345678.js?principal=alice",
        &[],
    )
    .await?;
    let _second_missing_response = request(
        delivery.router(),
        Method::GET,
        "/assets/order-ABCDEFGH.js?payload=secret",
        &[],
    )
    .await?;

    let observations = observer.responses();
    assert_eq!(observations.len(), 4);
    assert_eq!(observations[2].status().metric_label(), "404");
    assert_eq!(observations[2].asset_class().metric_label(), "script");
    assert_eq!(observations[2].cache_class().metric_label(), "none");
    assert_eq!(observations[0].status(), StaticResponseStatus::Ok);
    assert_eq!(observations[0].asset_class(), StaticAssetClass::Script);
    assert_eq!(observations[0].cache_class(), StaticCacheClass::Immutable);
    assert_eq!(
        observations[0].response_bytes(),
        u64::try_from(JAVASCRIPT.len())?
    );
    assert!(!observations[0].fallback());
    assert!(!observations[0].missing_asset());
    assert_eq!(observations[1].asset_class(), StaticAssetClass::Shell);
    assert_eq!(observations[1].cache_class(), StaticCacheClass::Revalidate);
    assert!(observations[1].fallback());
    assert_eq!(observations[2], observations[3]);
    assert_eq!(observations[2].status(), StaticResponseStatus::NotFound);
    assert_eq!(observations[2].asset_class(), StaticAssetClass::Script);
    assert_eq!(observations[2].cache_class(), StaticCacheClass::None);
    assert!(observations[2].missing_asset());
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
    assert!(!matched.headers().contains_key("content-security-policy"));
    assert_eq!(response_body(matched).await?, b"backend-not-found");
    assert_eq!(reserved.status(), StatusCode::NOT_FOUND);
    assert_default_production_security_headers(&reserved);
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
    assert_default_production_security_headers(&response);
    Ok(())
}
#[tokio::test]
async fn private_source_maps_can_be_uploaded_but_are_never_served() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    fixture.write_source_map()?;
    let mut config = fixture.config();
    config.source_maps = SourceMapPolicy::Private;
    let delivery = StaticDelivery::new(config)?;

    let response = request(
        delivery.router(),
        Method::GET,
        &format!("/{JAVASCRIPT_PATH}.map"),
        &[],
    )
    .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_default_production_security_headers(&response);
    Ok(())
}

#[test]
fn disabled_source_map_build_rejects_map_artifacts() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    fixture.write_source_map()?;
    let observer = Arc::new(RecordingObserver::default());
    assert_eq!(
        StaticDelivery::with_observer(fixture.config(), observer.clone()).err(),
        Some(StaticDeliveryError::UnexpectedSourceMap)
    );
    assert_eq!(
        observer.contract_mismatches(),
        vec![StaticContractMismatch::SourceMapPolicy]
    );
    Ok(())
}


#[tokio::test]
async fn source_maps_can_be_explicitly_served() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    fixture.write_source_map()?;
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
    assert_default_production_security_headers(&response);
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
fn readiness_observations_report_available_and_missing_builds() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let observer = Arc::new(RecordingObserver::default());
    let delivery = StaticDelivery::with_observer(fixture.config(), observer.clone())?;

    assert!(delivery.check_readiness().is_ok());
    fixture.remove(JAVASCRIPT_PATH)?;
    assert!(delivery.check_readiness().is_err());
    assert_eq!(observer.readiness(), vec![true, false]);
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
fn build_base_path_mismatch_is_normalized_for_observability() -> Result<(), Box<dyn Error>> {
    let fixture = BuildFixture::create()?;
    let mut config = fixture.config();
    config.base_path = "/console".to_owned();
    let observer = Arc::new(RecordingObserver::default());

    assert_eq!(
        StaticDelivery::with_observer(config, observer.clone()).err(),
        Some(StaticDeliveryError::IndexBasePathMismatch)
    );
    assert_eq!(
        observer.contract_mismatches(),
        vec![StaticContractMismatch::BasePath]
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
