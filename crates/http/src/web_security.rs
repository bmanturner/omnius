use std::collections::BTreeSet;

use axum::{
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use serde::{Deserialize, Deserializer, de::Error as _};
use thiserror::Error;
use url::Url;

/// One validated source expression in a Content Security Policy directive.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CspSource(String);

impl CspSource {
    /// Returns the canonical CSP source expression.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn kind(&self) -> CspSourceKind {
        match self.0.as_str() {
            "'none'" => CspSourceKind::None,
            "'self'" => CspSourceKind::SelfOrigin,
            "data:" => CspSourceKind::Data,
            "blob:" => CspSourceKind::Blob,
            value if value.starts_with("https://") => CspSourceKind::HttpsOrigin,
            value if value.starts_with("wss://") => CspSourceKind::WssOrigin,
            _ => unreachable!("CSP sources are validated when constructed"),
        }
    }
}

impl TryFrom<String> for CspSource {
    type Error = WebSecurityPolicyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if valid_csp_source(&value) {
            Ok(Self(value))
        } else {
            Err(WebSecurityPolicyError::InvalidCspSource)
        }
    }
}

impl TryFrom<&str> for CspSource {
    type Error = WebSecurityPolicyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for CspSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CspSourceKind {
    None,
    SelfOrigin,
    Data,
    Blob,
    HttpsOrigin,
    WssOrigin,
}

/// Production Content Security Policy directives used by the browser application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ContentSecurityPolicyConfig {
    /// Fallback policy for otherwise unspecified fetch directives.
    pub default_src: Vec<CspSource>,
    /// Executable script sources. Inline code, hashes, nonces, and `unsafe-eval` are unsupported.
    pub script_src: Vec<CspSource>,
    /// Stylesheet sources. Inline styles, hashes, and nonces are unsupported.
    pub style_src: Vec<CspSource>,
    /// Fetch, `EventSource`, and `WebSocket` origins.
    pub connect_src: Vec<CspSource>,
    /// Image sources.
    pub img_src: Vec<CspSource>,
    /// Font sources.
    pub font_src: Vec<CspSource>,
    /// Plugin/object sources. Production validation requires `none`.
    pub object_src: Vec<CspSource>,
    /// Allowed document base URL sources.
    pub base_uri: Vec<CspSource>,
    /// Allowed form submission origins.
    pub form_action: Vec<CspSource>,
    /// Allowed embedding ancestors. Only `none` or `self` is supported.
    pub frame_ancestors: Vec<CspSource>,
}

impl Default for ContentSecurityPolicyConfig {
    fn default() -> Self {
        Self {
            default_src: sources(&["'self'"]),
            script_src: sources(&["'self'"]),
            style_src: sources(&["'self'"]),
            connect_src: sources(&["'self'"]),
            img_src: sources(&["'self'", "data:"]),
            font_src: sources(&["'self'"]),
            object_src: sources(&["'none'"]),
            base_uri: sources(&["'self'"]),
            form_action: sources(&["'self'"]),
            frame_ancestors: sources(&["'none'"]),
        }
    }
}

fn sources(values: &[&str]) -> Vec<CspSource> {
    values
        .iter()
        .map(|value| CspSource((*value).to_owned()))
        .collect()
}

/// Browser capability controlled by the Permissions Policy response header.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionsPolicyFeature {
    /// Device motion sensors.
    Accelerometer,
    /// Ambient light sensor.
    AmbientLightSensor,
    /// Automatic media playback.
    Autoplay,
    /// Battery status.
    Battery,
    /// Interest-group browsing topics.
    BrowsingTopics,
    /// Camera capture.
    Camera,
    /// Display capture.
    DisplayCapture,
    /// Encrypted media extensions.
    EncryptedMedia,
    /// Fullscreen presentation.
    Fullscreen,
    /// Geolocation.
    Geolocation,
    /// Gyroscope.
    Gyroscope,
    /// Human interface devices.
    Hid,
    /// Federated identity credentials.
    IdentityCredentialsGet,
    /// Magnetometer.
    Magnetometer,
    /// Microphone capture.
    Microphone,
    /// MIDI devices.
    Midi,
    /// Payment request API.
    Payment,
    /// `WebAuthn` credential creation.
    PublickeyCredentialsCreate,
    /// `WebAuthn` credential retrieval.
    PublickeyCredentialsGet,
    /// Screen wake lock.
    ScreenWakeLock,
    /// Serial devices.
    Serial,
    /// USB devices.
    Usb,
    /// Web share API.
    WebShare,
    /// Immersive XR tracking.
    XrSpatialTracking,
}

impl PermissionsPolicyFeature {
    const ALL: [Self; 24] = [
        Self::Accelerometer,
        Self::AmbientLightSensor,
        Self::Autoplay,
        Self::Battery,
        Self::BrowsingTopics,
        Self::Camera,
        Self::DisplayCapture,
        Self::EncryptedMedia,
        Self::Fullscreen,
        Self::Geolocation,
        Self::Gyroscope,
        Self::Hid,
        Self::IdentityCredentialsGet,
        Self::Magnetometer,
        Self::Microphone,
        Self::Midi,
        Self::Payment,
        Self::PublickeyCredentialsCreate,
        Self::PublickeyCredentialsGet,
        Self::ScreenWakeLock,
        Self::Serial,
        Self::Usb,
        Self::WebShare,
        Self::XrSpatialTracking,
    ];

    const fn header_name(self) -> &'static str {
        match self {
            Self::Accelerometer => "accelerometer",
            Self::AmbientLightSensor => "ambient-light-sensor",
            Self::Autoplay => "autoplay",
            Self::Battery => "battery",
            Self::BrowsingTopics => "browsing-topics",
            Self::Camera => "camera",
            Self::DisplayCapture => "display-capture",
            Self::EncryptedMedia => "encrypted-media",
            Self::Fullscreen => "fullscreen",
            Self::Geolocation => "geolocation",
            Self::Gyroscope => "gyroscope",
            Self::Hid => "hid",
            Self::IdentityCredentialsGet => "identity-credentials-get",
            Self::Magnetometer => "magnetometer",
            Self::Microphone => "microphone",
            Self::Midi => "midi",
            Self::Payment => "payment",
            Self::PublickeyCredentialsCreate => "publickey-credentials-create",
            Self::PublickeyCredentialsGet => "publickey-credentials-get",
            Self::ScreenWakeLock => "screen-wake-lock",
            Self::Serial => "serial",
            Self::Usb => "usb",
            Self::WebShare => "web-share",
            Self::XrSpatialTracking => "xr-spatial-tracking",
        }
    }
}

/// Deny-by-default browser capability policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PermissionsPolicyConfig {
    /// Capabilities available to the serving origin. Every other known capability is disabled.
    pub allow_self: Vec<PermissionsPolicyFeature>,
}

impl Default for PermissionsPolicyConfig {
    fn default() -> Self {
        Self {
            allow_self: vec![
                PermissionsPolicyFeature::PublickeyCredentialsCreate,
                PermissionsPolicyFeature::PublickeyCredentialsGet,
            ],
        }
    }
}

/// Referrer information exposed by browser requests originating from the web application.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ReferrerPolicy {
    /// Send no referrer information.
    #[default]
    NoReferrer,
    /// Send the origin only for equally secure cross-origin requests.
    StrictOriginWhenCrossOrigin,
    /// Send referrers only to the same origin.
    SameOrigin,
}

impl ReferrerPolicy {
    const fn header_value(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::SameOrigin => "same-origin",
        }
    }
}

/// Boundary at which transport security is known to be enforced for the public origin.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBoundary {
    /// The application cannot assert that every public request uses trusted TLS.
    #[default]
    None,
    /// A directly managed listener or trusted terminating proxy enforces TLS for the public origin.
    Trusted,
}

/// HTTP Strict Transport Security policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HstsConfig {
    /// Explicit public TLS boundary. HSTS is emitted only for `trusted`.
    pub boundary: TlsBoundary,
    /// Browser HSTS lifetime.
    pub max_age_seconds: u64,
    /// Apply HSTS to subdomains.
    pub include_subdomains: bool,
    /// Request browser preload-list inclusion.
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            boundary: TlsBoundary::None,
            max_age_seconds: 31_536_000,
            include_subdomains: false,
            preload: false,
        }
    }
}

/// Cross-Origin-Opener-Policy mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginOpenerPolicy {
    /// Do not emit COOP.
    Disabled,
    /// Isolate the browsing context group.
    SameOrigin,
    /// Preserve trusted popup integrations.
    #[default]
    SameOriginAllowPopups,
}

impl CrossOriginOpenerPolicy {
    const fn header_value(self) -> Option<&'static str> {
        match self {
            Self::Disabled => None,
            Self::SameOrigin => Some("same-origin"),
            Self::SameOriginAllowPopups => Some("same-origin-allow-popups"),
        }
    }
}

/// Cross-Origin-Resource-Policy mode for served web files.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginResourcePolicy {
    /// Do not emit CORP.
    Disabled,
    /// Permit only the same origin.
    #[default]
    SameOrigin,
    /// Permit the same site.
    SameSite,
    /// Permit cross-origin use.
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    const fn header_value(self) -> Option<&'static str> {
        match self {
            Self::Disabled => None,
            Self::SameOrigin => Some("same-origin"),
            Self::SameSite => Some("same-site"),
            Self::CrossOrigin => Some("cross-origin"),
        }
    }
}

/// Cross-Origin-Embedder-Policy mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginEmbedderPolicy {
    /// Preserve compatibility with resources that do not opt into cross-origin isolation.
    #[default]
    Disabled,
    /// Require CORS or CORP for embedded cross-origin resources.
    RequireCorp,
    /// Load eligible cross-origin resources without credentials.
    Credentialless,
}

impl CrossOriginEmbedderPolicy {
    const fn header_value(self) -> Option<&'static str> {
        match self {
            Self::Disabled => None,
            Self::RequireCorp => Some("require-corp"),
            Self::Credentialless => Some("credentialless"),
        }
    }
}

/// Compatible cross-origin isolation settings for the browser application.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CrossOriginPolicyConfig {
    /// Browsing-context isolation.
    pub opener: CrossOriginOpenerPolicy,
    /// Resource embedding permission.
    pub resource: CrossOriginResourcePolicy,
    /// Cross-origin embedder isolation; disabled unless explicitly required.
    pub embedder: CrossOriginEmbedderPolicy,
}

/// Validated production response security policy for web files and static errors.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WebSecurityPolicy {
    /// Content Security Policy directives.
    pub content_security_policy: ContentSecurityPolicyConfig,
    /// Deny-by-default Permissions Policy.
    pub permissions_policy: PermissionsPolicyConfig,
    /// Browser referrer behavior.
    pub referrer_policy: ReferrerPolicy,
    /// Strict transport policy tied to an explicit trusted TLS boundary.
    pub hsts: HstsConfig,
    /// Optional compatible cross-origin isolation headers.
    pub cross_origin: CrossOriginPolicyConfig,
}

impl WebSecurityPolicy {
    /// Validates the production policy without assembling static delivery.
    ///
    /// Development HMR policies are intentionally not represented by this type.
    ///
    /// # Errors
    ///
    /// Returns [`WebSecurityPolicyError`] for an unsafe directive, ambiguous permission policy,
    /// untrusted HSTS configuration, or incompatible cross-origin isolation.
    pub fn validate(&self) -> Result<(), WebSecurityPolicyError> {
        ValidatedWebSecurityPolicy::new(self).map(|_| ())
    }

    pub(crate) fn into_validated(
        self,
    ) -> Result<ValidatedWebSecurityPolicy, WebSecurityPolicyError> {
        ValidatedWebSecurityPolicy::new(&self)
    }
}

/// Failure to validate a production browser security policy.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WebSecurityPolicyError {
    /// A CSP source expression is unsupported, malformed, or unsafe for production.
    #[error("production CSP contains an invalid or unsafe source")]
    InvalidCspSource,
    /// A required CSP directive is empty, duplicated, or contains an incompatible source.
    #[error("production CSP directive is invalid")]
    InvalidCspDirective,
    /// The Permissions Policy contains the same capability more than once.
    #[error("permissions policy contains a duplicate capability")]
    DuplicatePermission,
    /// HSTS settings are invalid for the selected TLS boundary.
    #[error("HSTS requires a valid explicit trusted TLS boundary")]
    InvalidHsts,
    /// Cross-origin isolation settings are incompatible.
    #[error("cross-origin isolation policy is incompatible")]
    IncompatibleCrossOriginIsolation,
    /// A validated policy could not be encoded as HTTP headers.
    #[error("web security policy cannot be encoded as response headers")]
    InvalidHeader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedWebSecurityPolicy {
    csp: HeaderValue,
    permissions: HeaderValue,
    referrer: HeaderValue,
    frame_options: HeaderValue,
    hsts: Option<HeaderValue>,
    opener: Option<HeaderValue>,
    resource: Option<HeaderValue>,
    embedder: Option<HeaderValue>,
}

impl ValidatedWebSecurityPolicy {
    fn new(config: &WebSecurityPolicy) -> Result<Self, WebSecurityPolicyError> {
        validate_content_security_policy(&config.content_security_policy)?;
        let content_security_policy = build_content_security_policy(
            &config.content_security_policy,
        )?;
        let permissions_policy = build_permissions_policy(&config.permissions_policy)?;
        let frame_options = match config
            .content_security_policy
            .frame_ancestors
            .first()
            .map(CspSource::kind)
        {
            Some(CspSourceKind::None) => HeaderValue::from_static("DENY"),
            Some(CspSourceKind::SelfOrigin) => HeaderValue::from_static("SAMEORIGIN"),
            _ => return Err(WebSecurityPolicyError::InvalidCspDirective),
        };
        let strict_transport_security = build_hsts(config.hsts)?;
        if config.cross_origin.embedder != CrossOriginEmbedderPolicy::Disabled
            && config.cross_origin.opener != CrossOriginOpenerPolicy::SameOrigin
        {
            return Err(WebSecurityPolicyError::IncompatibleCrossOriginIsolation);
        }
        Ok(Self {
            csp: content_security_policy,
            permissions: permissions_policy,
            referrer: HeaderValue::from_static(config.referrer_policy.header_value()),
            frame_options,
            hsts: strict_transport_security,
            opener: optional_header(config.cross_origin.opener.header_value()),
            resource: optional_header(config.cross_origin.resource.header_value()),
            embedder: optional_header(config.cross_origin.embedder.header_value()),
        })
    }

    pub(crate) fn apply(&self, response: &mut Response) {
        let headers = response.headers_mut();
        headers.insert("content-security-policy", self.csp.clone());
        headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
        headers.insert("x-frame-options", self.frame_options.clone());
        headers.insert("referrer-policy", self.referrer.clone());
        headers.insert("permissions-policy", self.permissions.clone());
        insert_optional(headers, "strict-transport-security", self.hsts.as_ref());
        insert_optional(headers, "cross-origin-opener-policy", self.opener.as_ref());
        insert_optional(headers, "cross-origin-resource-policy", self.resource.as_ref());
        insert_optional(headers, "cross-origin-embedder-policy", self.embedder.as_ref());
    }
}

fn valid_csp_source(value: &str) -> bool {
    if matches!(value, "'none'" | "'self'" | "data:" | "blob:") {
        return true;
    }
    if !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || !(value.starts_with("https://") || value.starts_with("wss://"))
    {
        return false;
    }
    let Ok(origin) = Url::parse(value) else {
        return false;
    };
    matches!(origin.scheme(), "https" | "wss")
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.host_str().is_some()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none()
}

fn validate_content_security_policy(
    config: &ContentSecurityPolicyConfig,
) -> Result<(), WebSecurityPolicyError> {
    validate_sources(
        &config.default_src,
        &[
            CspSourceKind::None,
            CspSourceKind::SelfOrigin,
            CspSourceKind::HttpsOrigin,
        ],
    )?;
    validate_sources(
        &config.script_src,
        &[CspSourceKind::None, CspSourceKind::SelfOrigin, CspSourceKind::HttpsOrigin],
    )?;
    validate_sources(
        &config.style_src,
        &[CspSourceKind::None, CspSourceKind::SelfOrigin, CspSourceKind::HttpsOrigin],
    )?;
    validate_sources(
        &config.connect_src,
        &[
            CspSourceKind::None,
            CspSourceKind::SelfOrigin,
            CspSourceKind::HttpsOrigin,
            CspSourceKind::WssOrigin,
        ],
    )?;
    validate_sources(
        &config.img_src,
        &[
            CspSourceKind::None,
            CspSourceKind::SelfOrigin,
            CspSourceKind::Data,
            CspSourceKind::Blob,
            CspSourceKind::HttpsOrigin,
        ],
    )?;
    validate_sources(
        &config.font_src,
        &[
            CspSourceKind::None,
            CspSourceKind::SelfOrigin,
            CspSourceKind::Data,
            CspSourceKind::HttpsOrigin,
        ],
    )?;
    validate_sources(&config.object_src, &[CspSourceKind::None])?;
    validate_sources(
        &config.base_uri,
        &[CspSourceKind::None, CspSourceKind::SelfOrigin],
    )?;
    validate_sources(
        &config.form_action,
        &[CspSourceKind::None, CspSourceKind::SelfOrigin, CspSourceKind::HttpsOrigin],
    )?;
    validate_sources(
        &config.frame_ancestors,
        &[CspSourceKind::None, CspSourceKind::SelfOrigin],
    )?;
    if config.object_src.len() != 1 || config.frame_ancestors.len() != 1 {
        return Err(WebSecurityPolicyError::InvalidCspDirective);
    }
    Ok(())
}

fn validate_sources(
    sources: &[CspSource],
    allowed: &[CspSourceKind],
) -> Result<(), WebSecurityPolicyError> {
    if sources.is_empty() {
        return Err(WebSecurityPolicyError::InvalidCspDirective);
    }
    let mut seen = BTreeSet::new();
    for source in sources {
        if !allowed.contains(&source.kind()) || !seen.insert(source.as_str()) {
            return Err(WebSecurityPolicyError::InvalidCspDirective);
        }
    }
    if sources.len() > 1 && sources.iter().any(|source| source.kind() == CspSourceKind::None) {
        return Err(WebSecurityPolicyError::InvalidCspDirective);
    }
    Ok(())
}

fn build_content_security_policy(
    config: &ContentSecurityPolicyConfig,
) -> Result<HeaderValue, WebSecurityPolicyError> {
    let directives = [
        ("default-src", config.default_src.as_slice()),
        ("script-src", config.script_src.as_slice()),
        ("style-src", config.style_src.as_slice()),
        ("connect-src", config.connect_src.as_slice()),
        ("img-src", config.img_src.as_slice()),
        ("font-src", config.font_src.as_slice()),
        ("object-src", config.object_src.as_slice()),
        ("base-uri", config.base_uri.as_slice()),
        ("form-action", config.form_action.as_slice()),
        ("frame-ancestors", config.frame_ancestors.as_slice()),
    ];
    let mut policy = String::with_capacity(256);
    for (index, (name, sources)) in directives.into_iter().enumerate() {
        if index != 0 {
            policy.push_str("; ");
        }
        policy.push_str(name);
        for source in sources {
            policy.push(' ');
            policy.push_str(source.as_str());
        }
    }
    HeaderValue::try_from(policy).map_err(|_| WebSecurityPolicyError::InvalidHeader)
}

fn build_permissions_policy(
    config: &PermissionsPolicyConfig,
) -> Result<HeaderValue, WebSecurityPolicyError> {
    let allowed: BTreeSet<_> = config.allow_self.iter().copied().collect();
    if allowed.len() != config.allow_self.len() {
        return Err(WebSecurityPolicyError::DuplicatePermission);
    }
    let mut policy = String::with_capacity(512);
    for (index, feature) in PermissionsPolicyFeature::ALL.into_iter().enumerate() {
        if index != 0 {
            policy.push_str(", ");
        }
        policy.push_str(feature.header_name());
        policy.push_str(if allowed.contains(&feature) {
            "=(self)"
        } else {
            "=()"
        });
    }
    HeaderValue::try_from(policy).map_err(|_| WebSecurityPolicyError::InvalidHeader)
}

fn build_hsts(config: HstsConfig) -> Result<Option<HeaderValue>, WebSecurityPolicyError> {
    if config.boundary == TlsBoundary::None {
        if config.include_subdomains || config.preload {
            return Err(WebSecurityPolicyError::InvalidHsts);
        }
        return Ok(None);
    }
    if config.max_age_seconds == 0 || config.max_age_seconds > 63_072_000 {
        return Err(WebSecurityPolicyError::InvalidHsts);
    }
    if config.preload && (!config.include_subdomains || config.max_age_seconds < 31_536_000) {
        return Err(WebSecurityPolicyError::InvalidHsts);
    }
    let max_age_seconds = config.max_age_seconds;
    let mut value = format!("max-age={max_age_seconds}");
    if config.include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if config.preload {
        value.push_str("; preload");
    }
    HeaderValue::try_from(value)
        .map(Some)
        .map_err(|_| WebSecurityPolicyError::InvalidHeader)
}

fn optional_header(value: Option<&'static str>) -> Option<HeaderValue> {
    value.map(HeaderValue::from_static)
}

fn insert_optional(headers: &mut HeaderMap, name: &'static str, value: Option<&HeaderValue>) {
    if let Some(value) = value {
        headers.insert(name, value.clone());
    } else {
        headers.remove(name);
    }
}
