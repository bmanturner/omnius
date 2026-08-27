use std::path::Path;

use axum::{
    http::{StatusCode, header},
    response::Response,
};

/// Bounded class of a browser-facing static response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticAssetClass {
    /// Application shell or an extensionless browser route.
    Shell,
    /// JavaScript module or chunk.
    Script,
    /// CSS stylesheet.
    Stylesheet,
    /// Raster, vector, or icon image.
    Image,
    /// Web font.
    Font,
    /// JavaScript or CSS source map.
    SourceMap,
    /// Another file under the built asset namespace.
    OtherAsset,
}

impl StaticAssetClass {
    /// Returns the fixed low-cardinality metrics label.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Script => "script",
            Self::Stylesheet => "stylesheet",
            Self::Image => "image",
            Self::Font => "font",
            Self::SourceMap => "source_map",
            Self::OtherAsset => "other_asset",
        }
    }

    pub(crate) const fn is_asset(self) -> bool {
        !matches!(self, Self::Shell)
    }
}

/// Bounded response status used by static delivery metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticResponseStatus {
    /// `200 OK`.
    Ok,
    /// `206 Partial Content`.
    PartialContent,
    /// `304 Not Modified`.
    NotModified,
    /// `404 Not Found`.
    NotFound,
    /// Another successful or redirect response.
    OtherSuccess,
    /// Another client error.
    ClientError,
    /// Server failure.
    ServerError,
}

impl StaticResponseStatus {
    fn from_status(status: StatusCode) -> Self {
        match status {
            StatusCode::OK => Self::Ok,
            StatusCode::PARTIAL_CONTENT => Self::PartialContent,
            StatusCode::NOT_MODIFIED => Self::NotModified,
            StatusCode::NOT_FOUND => Self::NotFound,
            value if value.is_success() || value.is_redirection() => Self::OtherSuccess,
            value if value.is_client_error() => Self::ClientError,
            _ => Self::ServerError,
        }
    }

    /// Returns the fixed low-cardinality metrics label.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Ok => "200",
            Self::PartialContent => "206",
            Self::NotModified => "304",
            Self::NotFound => "404",
            Self::OtherSuccess => "other_success",
            Self::ClientError => "other_4xx",
            Self::ServerError => "5xx",
        }
    }
}

/// Bounded cache treatment applied to a static response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticCacheClass {
    /// Fingerprinted immutable asset.
    Immutable,
    /// Revalidated application shell or non-fingerprinted success.
    Revalidate,
    /// Explicitly non-storable response.
    NoStore,
    /// No cache directive was applied, such as a static error.
    None,
}

impl StaticCacheClass {
    fn from_response(response: &Response) -> Self {
        match response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
        {
            Some("public, max-age=31536000, immutable") => Self::Immutable,
            Some("no-cache") => Self::Revalidate,
            Some("no-store") => Self::NoStore,
            _ => Self::None,
        }
    }

    /// Returns the fixed low-cardinality metrics label.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Immutable => "immutable",
            Self::Revalidate => "revalidate",
            Self::NoStore => "no_store",
            Self::None => "none",
        }
    }
}

/// One normalized static response observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticResponseObservation {
    status: StaticResponseStatus,
    asset_class: StaticAssetClass,
    cache_class: StaticCacheClass,
    response_bytes: u64,
    fallback: bool,
    missing_asset: bool,
}

impl StaticResponseObservation {
    pub(crate) fn from_response(
        response: &Response,
        asset_class: StaticAssetClass,
        fallback: bool,
        head_request: bool,
    ) -> Self {
        let status = StaticResponseStatus::from_status(response.status());
        let response_bytes = if head_request {
            0
        } else {
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
        };
        Self {
            status,
            asset_class,
            cache_class: StaticCacheClass::from_response(response),
            response_bytes,
            fallback,
            missing_asset: status == StaticResponseStatus::NotFound && asset_class.is_asset(),
        }
    }

    /// Returns the normalized response status.
    #[must_use]
    pub const fn status(self) -> StaticResponseStatus {
        self.status
    }

    /// Returns the normalized asset class.
    #[must_use]
    pub const fn asset_class(self) -> StaticAssetClass {
        self.asset_class
    }

    /// Returns the cache class.
    #[must_use]
    pub const fn cache_class(self) -> StaticCacheClass {
        self.cache_class
    }

    /// Returns the declared response bytes, or zero when no length was available.
    #[must_use]
    pub const fn response_bytes(self) -> u64 {
        self.response_bytes
    }

    /// Reports whether SPA fallback was attempted.
    #[must_use]
    pub const fn fallback(self) -> bool {
        self.fallback
    }

    /// Reports a missing request for a bounded asset class.
    #[must_use]
    pub const fn missing_asset(self) -> bool {
        self.missing_asset
    }
}

/// Normalized build contract mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticContractMismatch {
    /// The built shell URLs disagree with the configured public base path.
    BasePath,
    /// The selected source-map serving policy disagrees with the build output.
    SourceMapPolicy,
    /// The built shell contains active content incompatible with the production security policy.
    SecurityPolicy,
}

impl StaticContractMismatch {
    /// Returns the fixed low-cardinality metrics label.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::BasePath => "base_path",
            Self::SourceMapPolicy => "source_map_policy",
            Self::SecurityPolicy => "security_policy",
        }
    }
}

/// Hook for bounded static delivery metrics without exposing request identities or paths.
pub trait StaticDeliveryObserver: Send + Sync + 'static {
    /// Observes one completed static response.
    fn observe_response(&self, observation: StaticResponseObservation);

    /// Observes a static build readiness check.
    fn observe_readiness(&self, available: bool);

    /// Observes a build/runtime contract mismatch detected at assembly.
    fn observe_contract_mismatch(&self, mismatch: StaticContractMismatch);
}

/// Existing `metrics` facade adapter for static delivery observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct MetricsStaticDeliveryObserver;

impl StaticDeliveryObserver for MetricsStaticDeliveryObserver {
    fn observe_response(&self, observation: StaticResponseObservation) {
        let status = observation.status.metric_label();
        let asset_class = observation.asset_class.metric_label();
        let cache_class = observation.cache_class.metric_label();
        let fallback = bool_label(observation.fallback);
        metrics::counter!(
            "omnius_static_requests_total",
            "status" => status,
            "asset_class" => asset_class,
            "cache_class" => cache_class,
            "fallback" => fallback,
        )
        .increment(1);
        metrics::counter!(
            "omnius_static_response_bytes_total",
            "status" => status,
            "asset_class" => asset_class,
            "cache_class" => cache_class,
            "fallback" => fallback,
        )
        .increment(observation.response_bytes);
        if observation.missing_asset {
            metrics::counter!(
                "omnius_static_missing_assets_total",
                "asset_class" => asset_class,
            )
            .increment(1);
        }
    }

    fn observe_readiness(&self, available: bool) {
        metrics::counter!(
            "omnius_static_readiness_checks_total",
            "result" => if available { "available" } else { "unavailable" },
        )
        .increment(1);
    }

    fn observe_contract_mismatch(&self, mismatch: StaticContractMismatch) {
        metrics::counter!(
            "omnius_static_contract_mismatches_total",
            "reason" => mismatch.metric_label(),
        )
        .increment(1);
    }
}

pub(crate) fn classify_asset_path(path: &str) -> StaticAssetClass {
    let public_path = path.trim_start_matches('/');
    if public_path.is_empty() || public_path.ends_with('/') {
        return StaticAssetClass::Shell;
    }
    let Some(extension) = Path::new(public_path)
        .extension()
        .and_then(|value| value.to_str())
    else {
        return if public_path == "assets" || public_path.starts_with("assets/") {
            StaticAssetClass::OtherAsset
        } else {
            StaticAssetClass::Shell
        };
    };
    if matches_extension(extension, &["js", "mjs", "cjs"]) {
        StaticAssetClass::Script
    } else if matches_extension(extension, &["css"]) {
        StaticAssetClass::Stylesheet
    } else if matches_extension(
        extension,
        &["png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico"],
    ) {
        StaticAssetClass::Image
    } else if matches_extension(extension, &["woff", "woff2", "ttf", "otf", "eot"]) {
        StaticAssetClass::Font
    } else if matches_extension(extension, &["map"]) {
        StaticAssetClass::SourceMap
    } else {
        StaticAssetClass::OtherAsset
    }
}

fn matches_extension(extension: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

const fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}
