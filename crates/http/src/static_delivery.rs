use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use crate::{
    MetricsStaticDeliveryObserver, StaticAssetClass, StaticContractMismatch,
    StaticDeliveryObserver, WebSecurityPolicy, WebSecurityPolicyError,
    static_observability::{StaticResponseObservation, classify_asset_path},
    web_security::ValidatedWebSecurityPolicy,
};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, Uri, header},
    response::{IntoResponse as _, Response},
};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use thiserror::Error;
use tower::ServiceExt as _;
use tower_http::services::{ServeDir, ServeFile};

const INDEX_FILE: &str = "index.html";
const MANIFEST_FILE: &str = ".vite/manifest.json";
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const SHELL_CACHE_CONTROL: &str = "no-cache";

/// Shared backend route topology consumed by Rust static delivery and Vite development proxying.
pub const DEFAULT_ROUTE_TOPOLOGY_JSON: &str = include_str!("../web-route-topology.json");

/// Behavior used when a safe browser path does not identify a built file.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum StaticFallback {
    /// Serve the application shell for extensionless browser routes.
    #[default]
    Spa,
    /// Return a real `404 Not Found` response.
    NotFound,
}

/// Policy controlling direct delivery of JavaScript source maps.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceMapPolicy {
    /// Do not build or serve source maps.
    #[default]
    Disabled,
    /// Permit source maps in the build for private upload, but never serve them.
    Private,
    /// Permit source maps to be served as public assets.
    Public,
}

/// Precompressed sidecar formats that tower-http may negotiate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PrecompressedConfig {
    /// Negotiate `.gz` sidecars.
    pub gzip: bool,
    /// Negotiate `.br` sidecars.
    pub brotli: bool,
    /// Negotiate `.zst` sidecars.
    pub zstd: bool,
}

impl Default for PrecompressedConfig {
    fn default() -> Self {
        Self {
            gzip: true,
            brotli: true,
            zstd: true,
        }
    }
}

/// Static production delivery settings before path and policy validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct StaticDeliveryConfig {
    /// Vite output directory.
    pub asset_dir: PathBuf,
    /// Public URL base under which the browser application is served.
    pub base_path: String,
    /// Missing browser-route behavior.
    pub fallback: StaticFallback,
    /// Whether production startup requires and serves this build.
    pub production_required: bool,
    /// Explicitly serve the production build outside production, for browser integration tests.
    pub serve_in_nonproduction: bool,
    /// Direct source-map delivery policy.
    pub source_maps: SourceMapPolicy,
    /// Supported precompressed sidecars.
    pub precompressed: PrecompressedConfig,
    /// Validated production browser response security policy.
    pub security: WebSecurityPolicy,
}

impl Default for StaticDeliveryConfig {
    fn default() -> Self {
        Self {
            asset_dir: PathBuf::from("web/dist"),
            base_path: "/".to_owned(),
            fallback: StaticFallback::Spa,
            production_required: true,
            serve_in_nonproduction: false,
            source_maps: SourceMapPolicy::Disabled,
            precompressed: PrecompressedConfig::default(),
            security: WebSecurityPolicy::default(),
        }
    }
}

impl StaticDeliveryConfig {
    /// Validates URL and filesystem-independent configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StaticDeliveryError`] when the asset directory is empty, the base path is not a
    /// canonical absolute URL path, or the production web security policy is invalid.
    pub fn validate(self) -> Result<ValidatedStaticDeliveryConfig, StaticDeliveryError> {
        if self.asset_dir.as_os_str().is_empty() {
            return Err(StaticDeliveryError::EmptyAssetDirectory);
        }
        let base_path = normalize_base_path(&self.base_path)?;
        let security = self.security.into_validated()?;
        Ok(ValidatedStaticDeliveryConfig {
            asset_dir: self.asset_dir,
            base_path,
            fallback: self.fallback,
            production_required: self.production_required,
            source_maps: self.source_maps,
            precompressed: self.precompressed,
            security,
        })
    }
}

/// Filesystem-independent validated static delivery settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedStaticDeliveryConfig {
    asset_dir: PathBuf,
    base_path: String,
    fallback: StaticFallback,
    production_required: bool,
    source_maps: SourceMapPolicy,
    precompressed: PrecompressedConfig,
    security: ValidatedWebSecurityPolicy,
}

impl ValidatedStaticDeliveryConfig {
    /// Returns the Vite build directory.
    #[must_use]
    pub fn asset_dir(&self) -> &Path {
        &self.asset_dir
    }

    /// Returns the canonical public base path without a trailing slash, except for `/`.
    #[must_use]
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Returns whether production startup requires this build.
    #[must_use]
    pub const fn production_required(&self) -> bool {
        self.production_required
    }

    /// Returns the configured missing-route behavior.
    #[must_use]
    pub const fn fallback(&self) -> StaticFallback {
        self.fallback
    }

    /// Returns the configured source-map policy.
    #[must_use]
    pub const fn source_maps(&self) -> SourceMapPolicy {
        self.source_maps
    }
}

/// Backend route matching rule.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackendRouteMatch {
    /// Match only the exact path.
    Exact,
    /// Match the path and descendants separated by `/`.
    Prefix,
}

/// Backend route transport used by development proxy assembly.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackendTransport {
    /// Ordinary request/response HTTP.
    Http,
    /// WebSocket upgrade traffic.
    Websocket,
    /// Server-sent event streaming.
    Sse,
}

/// One reserved backend route from the shared topology.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackendRoute {
    path: String,
    #[serde(rename = "match")]
    route_match: BackendRouteMatch,
    transport: BackendTransport,
}

impl BackendRoute {
    /// Returns the canonical absolute backend path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the route matching rule.
    #[must_use]
    pub const fn route_match(&self) -> BackendRouteMatch {
        self.route_match
    }

    /// Returns the development transport.
    #[must_use]
    pub const fn transport(&self) -> BackendTransport {
        self.transport
    }

    fn matches(&self, request_path: &str) -> bool {
        match self.route_match {
            BackendRouteMatch::Exact => request_path == self.path,
            BackendRouteMatch::Prefix => {
                request_path == self.path
                    || request_path
                        .strip_prefix(&self.path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
        }
    }
}

/// Validated shared route topology.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteTopology {
    version: u32,
    routes: Vec<BackendRoute>,
}

impl RouteTopology {
    /// Parses and validates a machine-readable route topology.
    ///
    /// # Errors
    ///
    /// Returns [`RouteTopologyError`] for malformed JSON, unsupported versions, invalid paths, or
    /// duplicate route rules.
    pub fn from_json(json: &str) -> Result<Self, RouteTopologyError> {
        let topology: Self = serde_json::from_str(json).map_err(|_| RouteTopologyError::Decode)?;
        topology.validate()
    }

    /// Returns the topology version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the reserved backend routes.
    #[must_use]
    pub fn routes(&self) -> &[BackendRoute] {
        &self.routes
    }

    /// Reports whether a normalized request path belongs to a backend namespace.
    #[must_use]
    pub fn is_reserved(&self, request_path: &str) -> bool {
        self.routes.iter().any(|route| route.matches(request_path))
    }

    fn validate(self) -> Result<Self, RouteTopologyError> {
        if self.version != 1 {
            return Err(RouteTopologyError::UnsupportedVersion);
        }
        if self.routes.is_empty() {
            return Err(RouteTopologyError::Empty);
        }
        let mut identities = HashSet::with_capacity(self.routes.len());
        for route in &self.routes {
            if normalize_topology_path(&route.path).is_none() {
                return Err(RouteTopologyError::InvalidRoute);
            }
            if !identities.insert((route.path.as_str(), route.route_match)) {
                return Err(RouteTopologyError::DuplicateRoute);
            }
        }
        Ok(self)
    }
}

/// Failure to parse or validate the shared route topology.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RouteTopologyError {
    /// The JSON shape or value types are invalid.
    #[error("route topology could not be decoded")]
    Decode,
    /// The topology schema version is not supported.
    #[error("route topology version is unsupported")]
    UnsupportedVersion,
    /// No backend reservations were configured.
    #[error("route topology contains no routes")]
    Empty,
    /// A route is not a canonical absolute path.
    #[error("route topology contains an invalid route")]
    InvalidRoute,
    /// The same path and match rule occurs more than once.
    #[error("route topology contains a duplicate route")]
    DuplicateRoute,
}

/// Failure to validate or assemble production static delivery.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StaticDeliveryError {
    /// The configured asset directory is empty.
    #[error("static asset directory must not be empty")]
    EmptyAssetDirectory,
    /// The configured base path is not a canonical absolute URL path.
    #[error("static base path is invalid")]
    InvalidBasePath,
    /// The shared route topology is invalid.
    #[error("static backend route topology is invalid: {0}")]
    RouteTopology(#[from] RouteTopologyError),
    /// The production browser security policy is unsafe or incompatible.
    #[error("static web security policy is invalid: {0}")]
    SecurityPolicy(#[from] WebSecurityPolicyError),
    /// The configured build directory is missing, unreadable, or not a directory.
    #[error("static asset build is unavailable")]
    AssetDirectoryUnavailable,
    /// The build tree contains a symlink or cannot be inspected safely.
    #[error("static asset build tree is unsafe")]
    UnsafeAssetTree,
    /// The application shell is missing, unreadable, empty, or not a regular file.
    #[error("static application shell is unavailable")]
    IndexUnavailable,
    /// The application shell contains inline script or style content forbidden by the policy.
    #[error("static application shell contains forbidden inline active content")]
    IndexContainsInlineContent,
    /// The built shell asset URLs do not match the configured public base path.
    #[error("static application shell base path does not match configuration")]
    IndexBasePathMismatch,
    /// The Vite manifest is missing, unreadable, empty, or not a regular file.
    #[error("static Vite manifest is unavailable")]
    ManifestUnavailable,
    /// The Vite manifest is malformed or contains unsafe paths.
    #[error("static Vite manifest is invalid")]
    InvalidManifest,
    /// A fingerprinted file referenced by the Vite manifest is missing or unsafe.
    #[error("static Vite manifest references an unavailable asset")]
    ReferencedAssetUnavailable,
    /// Disabled source maps were found in the production build.
    #[error("static build contains source maps while source maps are disabled")]
    UnexpectedSourceMap,
}

/// Redacted readiness failure for a previously validated production build.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("static assets are unavailable")]
pub struct StaticReadinessError;

/// Validated Axum/tower-http production static delivery.
#[derive(Clone)]
pub struct StaticDelivery {
    inner: Arc<StaticDeliveryInner>,
}

struct StaticDeliveryInner {
    config: ValidatedStaticDeliveryConfig,
    topology: RouteTopology,
    files: ServeDir,
    index: ServeFile,
    required_paths: Arc<[PathBuf]>,
    observer: Arc<dyn StaticDeliveryObserver>,
}

impl std::fmt::Debug for StaticDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticDelivery")
            .field("base_path", &self.inner.config.base_path)
            .field("fallback", &self.inner.config.fallback)
            .field("source_maps", &self.inner.config.source_maps)
            .finish_non_exhaustive()
    }
}

impl StaticDelivery {
    /// Validates the default shared topology and required Vite build, then assembles file services.
    ///
    /// # Errors
    ///
    /// Returns [`StaticDeliveryError`] when configuration, topology, or required artifacts are
    /// invalid. Errors never include the configured filesystem path.
    pub fn new(config: StaticDeliveryConfig) -> Result<Self, StaticDeliveryError> {
        Self::with_observer(config, Arc::new(MetricsStaticDeliveryObserver))
    }
    /// Validates the default shared topology and required Vite build with an observability hook.
    ///
    /// # Errors
    ///
    /// Returns [`StaticDeliveryError`] when configuration, topology, or required artifacts are
    /// invalid.
    pub fn with_observer(
        config: StaticDeliveryConfig,
        observer: Arc<dyn StaticDeliveryObserver>,
    ) -> Result<Self, StaticDeliveryError> {
        let topology = RouteTopology::from_json(DEFAULT_ROUTE_TOPOLOGY_JSON)?;
        Self::with_topology_and_observer(config, topology, observer)
    }

    /// Validates an explicit shared topology and required Vite build.
    ///
    /// # Errors
    ///
    /// Returns [`StaticDeliveryError`] when configuration or required artifacts are invalid.
    pub fn with_topology(
        config: StaticDeliveryConfig,
        topology: RouteTopology,
    ) -> Result<Self, StaticDeliveryError> {
        Self::with_topology_and_observer(config, topology, Arc::new(MetricsStaticDeliveryObserver))
    }

    /// Validates an explicit topology and build with a normalized observability hook.
    ///
    /// # Errors
    ///
    /// Returns [`StaticDeliveryError`] when configuration or required artifacts are invalid.
    pub fn with_topology_and_observer(
        config: StaticDeliveryConfig,
        topology: RouteTopology,
        observer: Arc<dyn StaticDeliveryObserver>,
    ) -> Result<Self, StaticDeliveryError> {
        let topology = topology.validate()?;
        let config = config.validate()?;
        let build = validate_build(&config).inspect_err(|error| {
            if let Some(mismatch) = contract_mismatch(*error) {
                observer.observe_contract_mismatch(mismatch);
            }
        })?;
        let files = configure_directory_service(&config);
        let index = configure_file_service(&config, config.asset_dir.join(INDEX_FILE));
        Ok(Self {
            inner: Arc::new(StaticDeliveryInner {
                config,
                topology,
                files,
                index,
                required_paths: build.required_paths.into(),
                observer,
            }),
        })
    }

    /// Returns the canonical public base path.
    #[must_use]
    pub fn base_path(&self) -> &str {
        self.inner.config.base_path()
    }

    /// Rechecks required artifacts for readiness without exposing filesystem details.
    ///
    /// # Errors
    ///
    /// Returns [`StaticReadinessError`] when the build tree or a required artifact became
    /// unavailable after startup.
    pub fn check_readiness(&self) -> Result<(), StaticReadinessError> {
        let result = (|| {
            validate_asset_tree(&self.inner.config.asset_dir, self.inner.config.source_maps)
                .map_err(|_| StaticReadinessError)?;
            for (index, path) in self.inner.required_paths.iter().enumerate() {
                let metadata = fs::symlink_metadata(path).map_err(|_| StaticReadinessError)?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || (index < 2 && metadata.len() == 0)
                    || fs::File::open(path).is_err()
                {
                    return Err(StaticReadinessError);
                }
            }
            Ok(())
        })();
        self.inner.observer.observe_readiness(result.is_ok());
        result
    }

    /// Builds a stateless fallback router intended to be merged after every backend router.
    pub fn router(&self) -> Router {
        Router::new()
            .fallback(serve_static_request)
            .with_state(self.clone())
    }

    async fn serve(&self, request: Request<Body>) -> Response {
        let mut context = StaticRequestContext {
            head_request: request.method() == Method::HEAD,
            ..StaticRequestContext::default()
        };
        let mut response = self.serve_unsecured(request, &mut context).await;
        self.inner.config.security.apply(&mut response);
        self.inner
            .observer
            .observe_response(StaticResponseObservation::from_response(
                &response,
                context.asset_class,
                context.fallback,
                context.head_request,
            ));
        response
    }

    async fn serve_unsecured(
        &self,
        mut request: Request<Body>,
        context: &mut StaticRequestContext,
    ) -> Response {
        if request.method() != Method::GET && request.method() != Method::HEAD {
            return StatusCode::NOT_FOUND.into_response();
        }

        let raw_path = request.uri().path();
        let Some(decoded_path) = decode_request_path(raw_path) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if self.inner.topology.is_reserved(&decoded_path) {
            return StatusCode::NOT_FOUND.into_response();
        }
        let Some(relative_raw_path) = relative_request_path(raw_path, &self.inner.config.base_path)
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Ok(relative_uri) = relative_raw_path.parse::<Uri>() else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Some(relative_decoded_path) =
            relative_request_path(&decoded_path, &self.inner.config.base_path).map(str::to_owned)
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        context.asset_class = classify_asset_path(&relative_decoded_path);
        if is_forbidden_public_path(&decoded_path, self.inner.config.source_maps) {
            return StatusCode::NOT_FOUND.into_response();
        }

        let fallback_request = (self.inner.config.fallback == StaticFallback::Spa
            && is_spa_route(&relative_decoded_path))
        .then(|| clone_empty_request(&request));
        *request.uri_mut() = relative_uri;

        let mut response = match self.inner.files.clone().oneshot(request).await {
            Ok(response) => response.map(Body::new),
            Err(error) => match error {},
        };
        if response.status() == StatusCode::NOT_FOUND
            && let Some(mut index_request) = fallback_request
        {
            context.fallback = true;
            *index_request.uri_mut() = Uri::from_static("/index.html");
            response = match self.inner.index.clone().oneshot(index_request).await {
                Ok(response) => response.map(Body::new),
                Err(error) => match error {},
            };
        }
        apply_cache_policy(&mut response, &relative_decoded_path);
        response
    }
}
struct StaticRequestContext {
    asset_class: StaticAssetClass,
    fallback: bool,
    head_request: bool,
}

impl Default for StaticRequestContext {
    fn default() -> Self {
        Self {
            asset_class: StaticAssetClass::Shell,
            fallback: false,
            head_request: false,
        }
    }
}

const fn contract_mismatch(error: StaticDeliveryError) -> Option<StaticContractMismatch> {
    match error {
        StaticDeliveryError::IndexContainsInlineContent => {
            Some(StaticContractMismatch::SecurityPolicy)
        }
        StaticDeliveryError::IndexBasePathMismatch => Some(StaticContractMismatch::BasePath),
        StaticDeliveryError::UnexpectedSourceMap => Some(StaticContractMismatch::SourceMapPolicy),
        _ => None,
    }
}

async fn serve_static_request(
    State(delivery): State<StaticDelivery>,
    request: Request<Body>,
) -> Response {
    delivery.serve(request).await
}

fn configure_directory_service(config: &ValidatedStaticDeliveryConfig) -> ServeDir {
    let mut service = ServeDir::new(&config.asset_dir).append_index_html_on_directories(true);
    if config.base_path != "/" {
        service = service.redirect_path_prefix(config.base_path.as_str());
    }
    configure_precompressed_directory(service, config.precompressed)
}

fn configure_precompressed_directory(
    mut service: ServeDir,
    precompressed: PrecompressedConfig,
) -> ServeDir {
    if precompressed.gzip {
        service = service.precompressed_gzip();
    }
    if precompressed.brotli {
        service = service.precompressed_br();
    }
    if precompressed.zstd {
        service = service.precompressed_zstd();
    }
    service
}

fn configure_file_service(config: &ValidatedStaticDeliveryConfig, path: PathBuf) -> ServeFile {
    let mut service = ServeFile::new(path);
    if config.precompressed.gzip {
        service = service.precompressed_gzip();
    }
    if config.precompressed.brotli {
        service = service.precompressed_br();
    }
    if config.precompressed.zstd {
        service = service.precompressed_zstd();
    }
    service
}

fn clone_empty_request(request: &Request<Body>) -> Request<Body> {
    let mut cloned = Request::new(Body::empty());
    *cloned.method_mut() = request.method().clone();
    *cloned.version_mut() = request.version();
    *cloned.headers_mut() = request.headers().clone();
    cloned
}

fn apply_cache_policy(response: &mut Response, relative_path: &str) {
    if !(response.status().is_success() || response.status() == StatusCode::NOT_MODIFIED) {
        return;
    }
    let path = relative_path.trim_start_matches('/');
    let value = if is_fingerprinted_asset(path) {
        IMMUTABLE_CACHE_CONTROL
    } else {
        SHELL_CACHE_CONTROL
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(value),
    );
}

struct ValidatedBuild {
    required_paths: Vec<PathBuf>,
}

#[derive(Deserialize)]
struct ViteManifestEntry {
    file: String,
    #[serde(default, rename = "isEntry")]
    is_entry: bool,
    #[serde(default)]
    css: Vec<String>,
    #[serde(default)]
    assets: Vec<String>,
}

fn validate_build(
    config: &ValidatedStaticDeliveryConfig,
) -> Result<ValidatedBuild, StaticDeliveryError> {
    validate_asset_tree(&config.asset_dir, config.source_maps)?;

    let index_path = config.asset_dir.join(INDEX_FILE);
    validate_nonempty_file(&index_path).map_err(|()| StaticDeliveryError::IndexUnavailable)?;
    let index_bytes = fs::read(&index_path).map_err(|_| StaticDeliveryError::IndexUnavailable)?;
    let index =
        std::str::from_utf8(&index_bytes).map_err(|_| StaticDeliveryError::IndexUnavailable)?;

    validate_index_active_content(index)?;
    let manifest_path = config.asset_dir.join(MANIFEST_FILE);
    validate_nonempty_file(&manifest_path)
        .map_err(|()| StaticDeliveryError::ManifestUnavailable)?;
    let manifest_bytes =
        fs::read(&manifest_path).map_err(|_| StaticDeliveryError::ManifestUnavailable)?;
    let manifest: BTreeMap<String, ViteManifestEntry> = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| StaticDeliveryError::InvalidManifest)?;
    if manifest.is_empty() {
        return Err(StaticDeliveryError::InvalidManifest);
    }

    let mut referenced = BTreeSet::new();
    for entry in manifest.values() {
        referenced.insert(entry.file.as_str());
        referenced.extend(entry.css.iter().map(String::as_str));
        referenced.extend(entry.assets.iter().map(String::as_str));
    }
    if referenced.is_empty() {
        return Err(StaticDeliveryError::InvalidManifest);
    }

    let mut required_paths =
        Vec::with_capacity(referenced.len().saturating_mul(4).saturating_add(2));
    required_paths.push(index_path);
    required_paths.push(manifest_path);
    for relative in referenced {
        if !is_safe_manifest_asset(relative, config.source_maps)
            || !is_fingerprinted_asset(relative)
        {
            return Err(StaticDeliveryError::InvalidManifest);
        }
        let path = config.asset_dir.join(relative);
        validate_regular_file(&path)
            .map_err(|()| StaticDeliveryError::ReferencedAssetUnavailable)?;
        for suffix in [
            config.precompressed.gzip.then_some(".gz"),
            config.precompressed.brotli.then_some(".br"),
            config.precompressed.zstd.then_some(".zst"),
        ]
        .into_iter()
        .flatten()
        {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            match fs::symlink_metadata(&sidecar) {
                Ok(_) => validate_regular_file(&sidecar)
                    .map_err(|()| StaticDeliveryError::ReferencedAssetUnavailable)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(StaticDeliveryError::ReferencedAssetUnavailable),
            }
            required_paths.push(sidecar);
        }
        required_paths.push(path);
    }
    validate_index_base_path(index, &manifest, &config.base_path)?;

    Ok(ValidatedBuild { required_paths })
}

fn validate_index_base_path(
    index: &str,

    manifest: &BTreeMap<String, ViteManifestEntry>,
    base_path: &str,
) -> Result<(), StaticDeliveryError> {
    let public_prefix = if base_path == "/" {
        Cow::Borrowed("/")
    } else {
        Cow::Owned(format!("{base_path}/"))
    };
    let mut entry_count = 0;
    for entry in manifest.values().filter(|entry| entry.is_entry) {
        entry_count += 1;
        if !index.contains(&format!("{public_prefix}{}", entry.file))
            || entry
                .css
                .iter()
                .any(|asset| !index.contains(&format!("{public_prefix}{asset}")))
        {
            return Err(StaticDeliveryError::IndexBasePathMismatch);
        }
    }
    if entry_count == 0 {
        return Err(StaticDeliveryError::InvalidManifest);
    }
    Ok(())
}
fn validate_index_active_content(index: &str) -> Result<(), StaticDeliveryError> {
    let normalized = index.to_ascii_lowercase();
    if normalized.contains("<style") || normalized.contains("style=") {
        return Err(StaticDeliveryError::IndexContainsInlineContent);
    }
    let mut remainder = normalized.as_str();
    while let Some(start) = remainder.find("<script") {
        let script = &remainder[start..];
        let Some(open_end) = script.find('>') else {
            return Err(StaticDeliveryError::IndexContainsInlineContent);
        };
        let opening = &script[..open_end];
        if !opening
            .split_ascii_whitespace()
            .any(|attribute| attribute.starts_with("src="))
        {
            return Err(StaticDeliveryError::IndexContainsInlineContent);
        }
        let body_and_close = &script[open_end + 1..];
        let Some(close_start) = body_and_close.find("</script>") else {
            return Err(StaticDeliveryError::IndexContainsInlineContent);
        };
        if !body_and_close[..close_start].trim().is_empty() {
            return Err(StaticDeliveryError::IndexContainsInlineContent);
        }
        remainder = &body_and_close[close_start + "</script>".len()..];
    }
    Ok(())
}

fn validate_asset_tree(
    root: &Path,
    source_maps: SourceMapPolicy,
) -> Result<(), StaticDeliveryError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|_| StaticDeliveryError::AssetDirectoryUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StaticDeliveryError::AssetDirectoryUnavailable);
    }
    validate_directory_entries(root, source_maps)
}

fn validate_directory_entries(
    directory: &Path,
    source_maps: SourceMapPolicy,
) -> Result<(), StaticDeliveryError> {
    let entries = fs::read_dir(directory).map_err(|_| StaticDeliveryError::UnsafeAssetTree)?;
    for entry in entries {
        let entry = entry.map_err(|_| StaticDeliveryError::UnsafeAssetTree)?;
        let file_type = entry
            .file_type()
            .map_err(|_| StaticDeliveryError::UnsafeAssetTree)?;
        if file_type.is_symlink() || (!file_type.is_dir() && !file_type.is_file()) {
            return Err(StaticDeliveryError::UnsafeAssetTree);
        }
        if file_type.is_dir() {
            validate_directory_entries(&entry.path(), source_maps)?;
        } else if source_maps == SourceMapPolicy::Disabled
            && entry
                .file_name()
                .to_str()
                .is_some_and(is_source_map_artifact)
        {
            return Err(StaticDeliveryError::UnexpectedSourceMap);
        }
    }
    Ok(())
}

fn is_source_map_artifact(filename: &str) -> bool {
    let bytes = filename.as_bytes();
    [b".map".as_slice(), b".map.gz", b".map.br", b".map.zst"]
        .into_iter()
        .any(|suffix| {
            bytes
                .get(bytes.len().saturating_sub(suffix.len())..)
                .is_some_and(|ending| ending.eq_ignore_ascii_case(suffix))
        })
}

fn validate_nonempty_file(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || fs::File::open(path).is_err()
    {
        return Err(());
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || fs::File::open(path).is_err() {
        return Err(());
    }
    Ok(())
}

fn is_safe_manifest_asset(path: &str, source_maps: SourceMapPolicy) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', '\0', '%'])
        || is_forbidden_public_path(path, source_maps)
    {
        return false;
    }
    Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

fn is_fingerprinted_asset(path: &str) -> bool {
    if !path.starts_with("assets/") {
        return false;
    }
    let Some(filename) = Path::new(path).file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let stem = filename
        .split_once('.')
        .map_or(filename, |(stem, _extension)| stem);
    stem.match_indices('-').any(|(index, _)| {
        let hash = &stem[index + 1..];
        hash.len() >= 8
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn normalize_base_path(path: &str) -> Result<String, StaticDeliveryError> {
    if !path.starts_with('/') || path.contains(['?', '#', '%', '\\', '\0']) || path.contains("//") {
        return Err(StaticDeliveryError::InvalidBasePath);
    }
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        return Ok("/".to_owned());
    }
    if normalized.split('/').skip(1).any(|segment| {
        segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    }) {
        return Err(StaticDeliveryError::InvalidBasePath);
    }
    Ok(normalized.to_owned())
}

fn normalize_topology_path(path: &str) -> Option<&str> {
    if path == "/"
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['?', '#', '%', '\\', '\0'])
        || path.contains("//")
        || path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        None
    } else {
        Some(path)
    }
}

fn decode_request_path(raw_path: &str) -> Option<Cow<'_, str>> {
    let bytes = raw_path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return None;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let decoded = percent_decode_str(raw_path).decode_utf8().ok()?;
    if !is_normalized_request_path(&decoded) {
        return None;
    }
    Some(decoded)
}

fn is_normalized_request_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains(['\\', '\0']) {
        return false;
    }
    let mut segments = path.split('/').skip(1).peekable();
    while let Some(segment) = segments.next() {
        if matches!(segment, "." | "..") || (segment.is_empty() && segments.peek().is_some()) {
            return false;
        }
    }
    true
}

fn relative_request_path<'path>(request_path: &'path str, base_path: &str) -> Option<&'path str> {
    if base_path == "/" {
        return Some(request_path);
    }
    if request_path == base_path {
        return Some("/");
    }
    request_path
        .strip_prefix(base_path)
        .filter(|suffix| suffix.starts_with('/'))
}

fn is_forbidden_public_path(path: &str, source_maps: SourceMapPolicy) -> bool {
    let mut last = "";
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        last = segment;
        if segment.starts_with('.')
            || ["src", "source", "contracts", "packages", "node_modules"]
                .iter()
                .any(|reserved| segment.eq_ignore_ascii_case(reserved))
        {
            return true;
        }
    }
    if [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.toml",
        "cargo.lock",
        "openapi.json",
        "asyncapi.json",
        "permissions.json",
        "capabilities.json",
        "contract-manifest.json",
    ]
    .iter()
    .any(|reserved| last.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    let extension = Path::new(last).extension().and_then(|value| value.to_str());
    extension.is_some_and(|value| {
        ["br", "gz", "zst", "ts", "tsx", "mts", "cts", "rs", "toml"]
            .iter()
            .any(|blocked| value.eq_ignore_ascii_case(blocked))
    }) || (source_maps != SourceMapPolicy::Public
        && extension.is_some_and(|value| value.eq_ignore_ascii_case("map")))
}

fn is_spa_route(relative_path: &str) -> bool {
    let public_path = relative_path.trim_start_matches('/');
    if public_path == "assets" || public_path.starts_with("assets/") {
        return false;
    }
    relative_path.ends_with('/')
        || Path::new(relative_path)
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|filename| !filename.contains('.'))
}
