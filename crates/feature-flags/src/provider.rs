use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
};

use open_feature::{
    EvaluationReason as OpenFeatureReason,
    provider::{FeatureProvider as OpenFeatureSdkProvider, ProviderStatus, ResolutionDetails},
};
use rsk_auth_core::PrincipalKind;
use thiserror::Error;

use crate::{
    EvaluationContext, Flag, FlagKey, FlagObject, FlagString, FlagValue, FlagValueKind,
    FlagValueType, MAX_FLAG_OBJECT_FIELDS, context::SdkContextValue,
};

/// Maximum static flags in one in-process provider.
pub const MAX_STATIC_FLAGS: usize = 1_024;
/// Maximum provider variation identifier length retained in exposures.
pub const MAX_VARIANT_BYTES: usize = 64;

/// Fixed low-cardinality provider identity used by metrics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderKind {
    /// The bounded in-process provider.
    Static,
    /// An official `OpenFeature` SDK provider.
    OpenFeature,
    /// Another application adapter implementing [`FeatureFlagProvider`].
    Custom,
}

impl ProviderKind {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::OpenFeature => "open_feature",
            Self::Custom => "custom",
        }
    }
}

/// Safe provider failure classes. Provider messages and diagnostics are never retained.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    /// The configured provider is not ready or could not be reached.
    #[error("feature-flag provider is unavailable")]
    Unavailable,
    /// The provider has no value for the key.
    #[error("feature flag was not found")]
    NotFound,
    /// The provider rejected the bounded context.
    #[error("feature-flag provider rejected the evaluation context")]
    ContextRejected,
    /// The provider returned an invalid, mismatched, or unbounded response.
    #[error("feature-flag provider returned an invalid response")]
    InvalidResponse,
}

/// A bounded provider evaluation reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderReason {
    /// Static provider data.
    Static,
    /// A targeting rule matched.
    TargetingMatch,
    /// A fractional assignment matched.
    Split,
    /// Provider-side product disabling.
    Disabled,
    /// The provider did not supply a recognized reason.
    Unknown,
}

/// A bounded provider variation identifier.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Variant(String);

impl Variant {
    /// Validates and owns a log-safe provider variation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderResponseError`] for empty, oversized, or unsafe values.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderResponseError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProviderResponseError::InvalidVariant);
        }
        if value.len() > MAX_VARIANT_BYTES {
            return Err(ProviderResponseError::InvalidVariant);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ProviderResponseError::InvalidVariant);
        }
        Ok(Self(value))
    }

    /// Returns the bounded variation identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Variant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Variant").field(&self.0).finish()
    }
}

/// A provider response field violated the application boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderResponseError {
    /// Variation identifiers are non-empty, at most 64 bytes, and log-safe ASCII.
    #[error("provider variant is invalid")]
    InvalidVariant,
}

/// A provider's validated, untyped result.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderEvaluation {
    value: FlagValue,
    variant: Option<Variant>,
    reason: ProviderReason,
}

impl ProviderEvaluation {
    /// Creates a validated provider result with an unknown reason and no variation identifier.
    #[must_use]
    pub const fn new(value: FlagValue) -> Self {
        Self {
            value,
            variant: None,
            reason: ProviderReason::Unknown,
        }
    }

    /// Adds a bounded variation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderResponseError`] when the identifier is unsafe or oversized.
    pub fn with_variant(
        mut self,
        variant: impl Into<String>,
    ) -> Result<Self, ProviderResponseError> {
        self.variant = Some(Variant::new(variant)?);
        Ok(self)
    }

    /// Adds a closed provider reason.
    #[must_use]
    pub const fn with_reason(mut self, reason: ProviderReason) -> Self {
        self.reason = reason;
        self
    }

    /// Returns the validated value.
    #[must_use]
    pub const fn value(&self) -> &FlagValue {
        &self.value
    }

    /// Returns the bounded variation identifier, when supplied.
    #[must_use]
    pub const fn variant(&self) -> Option<&Variant> {
        self.variant.as_ref()
    }

    /// Returns the normalized provider reason.
    #[must_use]
    pub const fn reason(&self) -> ProviderReason {
        self.reason
    }
}

/// One borrowed, bounded provider request.
#[derive(Clone, Copy, Debug)]
pub struct ProviderRequest<'request> {
    key: &'request FlagKey,
    value_kind: FlagValueKind,
    context: &'request EvaluationContext,
}

impl<'request> ProviderRequest<'request> {
    pub(crate) const fn new(
        key: &'request FlagKey,
        value_kind: FlagValueKind,
        context: &'request EvaluationContext,
    ) -> Self {
        Self {
            key,
            value_kind,
            context,
        }
    }

    /// Returns the bounded flag key.
    #[must_use]
    pub const fn key(self) -> &'request FlagKey {
        self.key
    }

    /// Returns the requested typed value kind.
    #[must_use]
    pub const fn value_kind(self) -> FlagValueKind {
        self.value_kind
    }

    /// Returns the bounded evaluation context.
    #[must_use]
    pub const fn context(self) -> &'request EvaluationContext {
        self.context
    }
}

/// Object-safe asynchronous provider future.
pub type ProviderFuture<'request> =
    Pin<Box<dyn Future<Output = Result<ProviderEvaluation, ProviderError>> + Send + 'request>>;

/// Application-owned provider boundary wrapped by timeout, caching, safe defaults, and exposure
/// recording in [`crate::FeatureFlagEvaluator`].
pub trait FeatureFlagProvider: Send + Sync + 'static {
    /// Returns a fixed low-cardinality provider class.
    fn kind(&self) -> ProviderKind;

    /// Resolves one borrowed validated request.
    fn evaluate<'request>(
        &'request self,
        request: ProviderRequest<'request>,
    ) -> ProviderFuture<'request>;
}

#[derive(Clone)]
struct StaticEntry {
    value: FlagValue,
    variant: Variant,
}

/// Bounded in-process provider for tests and small deployments.
pub struct StaticProvider {
    entries: HashMap<FlagKey, StaticEntry>,
}

impl StaticProvider {
    /// Creates an empty bounded static provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Inserts or replaces a value using a typed flag definition.
    ///
    /// # Errors
    ///
    /// Returns [`StaticProviderError::Capacity`] when a new key would exceed the fixed limit.
    pub fn set<T: FlagValueType>(
        &mut self,
        flag: &Flag<T>,
        value: T,
    ) -> Result<(), StaticProviderError> {
        value
            .validate()
            .map_err(|_| StaticProviderError::InvalidValue)?;
        let at_capacity = self.entries.len() >= MAX_STATIC_FLAGS;
        let entry = StaticEntry {
            value: value.into_untyped(),
            variant: Variant("static".to_owned()),
        };
        match self.entries.entry(flag.key().clone()) {
            Entry::Occupied(mut current) => {
                current.insert(entry);
            }
            Entry::Vacant(vacant) => {
                if at_capacity {
                    return Err(StaticProviderError::Capacity);
                }
                vacant.insert(entry);
            }
        }
        Ok(())
    }

    /// Returns the number of configured flag values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no static values are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for StaticProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StaticProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticProvider")
            .field("entry_count", &self.entries.len())
            .field("entries", &"[REDACTED]")
            .finish()
    }
}

impl FeatureFlagProvider for StaticProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Static
    }

    fn evaluate<'request>(
        &'request self,
        request: ProviderRequest<'request>,
    ) -> ProviderFuture<'request> {
        Box::pin(async move {
            let entry = self
                .entries
                .get(request.key())
                .ok_or(ProviderError::NotFound)?;
            if entry.value.kind() != request.value_kind() {
                return Err(ProviderError::InvalidResponse);
            }
            Ok(ProviderEvaluation {
                value: entry.value.clone(),
                variant: Some(entry.variant.clone()),
                reason: ProviderReason::Static,
            })
        })
    }
}

/// Static provider construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StaticProviderError {
    /// The provider is capped at 1024 keys.
    #[error("static feature-flag provider exceeds 1024 entries")]
    Capacity,
    /// A value was not representable within the typed boundary.
    #[error("static feature-flag value is invalid")]
    InvalidValue,
}

/// Exact adapter from an official `open-feature` 0.3.0 provider to the application boundary.
///
/// The adapter invokes SDK resolver methods directly rather than an SDK [`open_feature::Client`].
/// This prevents client/global contexts and hooks from adding unbounded or non-allowlisted fields.
pub struct OpenFeatureProvider {
    provider: Arc<dyn OpenFeatureSdkProvider>,
}

impl OpenFeatureProvider {
    /// Wraps an initialized `OpenFeature` SDK provider.
    #[must_use]
    pub fn new(provider: Arc<dyn OpenFeatureSdkProvider>) -> Self {
        Self { provider }
    }

    fn sdk_context(context: &EvaluationContext) -> open_feature::EvaluationContext {
        let mut sdk_context = open_feature::EvaluationContext::default();
        if let Some(subject_id) = context.subject_id() {
            sdk_context.targeting_key = Some(subject_id.to_string());
        }
        if let Some(tenant_id) = context.tenant_id() {
            sdk_context.add_custom_field("tenant_id", tenant_id.to_string());
        }
        if let Some(kind) = context.principal_kind() {
            sdk_context.add_custom_field(
                "principal_kind",
                match kind {
                    PrincipalKind::User => "user",
                    PrincipalKind::ServiceAccount => "service_account",
                },
            );
        }
        for (attribute, value) in context.attributes() {
            let name = attribute.as_str();
            match value.as_sdk_value() {
                SdkContextValue::String(value) => sdk_context.add_custom_field(name, value),
                SdkContextValue::Boolean(value) => sdk_context.add_custom_field(name, value),
                SdkContextValue::Integer(value) => sdk_context.add_custom_field(name, value),
            }
        }
        sdk_context
    }
}

impl fmt::Debug for OpenFeatureProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenFeatureProvider")
            .field("provider", &"[REDACTED]")
            .finish()
    }
}

impl FeatureFlagProvider for OpenFeatureProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::OpenFeature
    }

    fn evaluate<'request>(
        &'request self,
        request: ProviderRequest<'request>,
    ) -> ProviderFuture<'request> {
        Box::pin(async move {
            if self.provider.status() != ProviderStatus::Ready {
                return Err(ProviderError::Unavailable);
            }
            let context = Self::sdk_context(request.context());
            let details = match request.value_kind() {
                FlagValueKind::Boolean => self
                    .provider
                    .resolve_bool_value(request.key().as_str(), &context)
                    .await
                    .map(|details| details.map_value(FlagValue::boolean)),
                FlagValueKind::Integer => self
                    .provider
                    .resolve_int_value(request.key().as_str(), &context)
                    .await
                    .map(|details| details.map_value(FlagValue::integer)),
                FlagValueKind::Float => self
                    .provider
                    .resolve_float_value(request.key().as_str(), &context)
                    .await
                    .and_then(|details| {
                        let ResolutionDetails {
                            value,
                            variant,
                            reason,
                            flag_metadata,
                        } = details;
                        let value =
                            FlagValue::float(value).map_err(|_| open_feature::EvaluationError {
                                code: open_feature::EvaluationErrorCode::TypeMismatch,
                                message: None,
                            })?;
                        Ok(ResolutionDetails {
                            value,
                            variant,
                            reason,
                            flag_metadata,
                        })
                    }),
                FlagValueKind::String => self
                    .provider
                    .resolve_string_value(request.key().as_str(), &context)
                    .await
                    .and_then(|details| {
                        let ResolutionDetails {
                            value,
                            variant,
                            reason,
                            flag_metadata,
                        } = details;
                        let value =
                            FlagString::new(value).map_err(|_| open_feature::EvaluationError {
                                code: open_feature::EvaluationErrorCode::TypeMismatch,
                                message: None,
                            })?;
                        Ok(ResolutionDetails {
                            value: FlagValue::string(value),
                            variant,
                            reason,
                            flag_metadata,
                        })
                    }),
                FlagValueKind::Object => self
                    .provider
                    .resolve_struct_value(request.key().as_str(), &context)
                    .await
                    .and_then(|details| {
                        let ResolutionDetails {
                            value,
                            variant,
                            reason,
                            flag_metadata,
                        } = details;
                        let value = bounded_sdk_object(value)?;
                        Ok(ResolutionDetails {
                            value: FlagValue::object(value),
                            variant,
                            reason,
                            flag_metadata,
                        })
                    }),
            }
            .map_err(|error| map_sdk_error(&error))?;
            map_sdk_details(details)
        })
    }
}

trait MapResolutionValue<T> {
    fn map_value<U>(self, map: impl FnOnce(T) -> U) -> ResolutionDetails<U>;
}

impl<T> MapResolutionValue<T> for ResolutionDetails<T> {
    fn map_value<U>(self, map: impl FnOnce(T) -> U) -> ResolutionDetails<U> {
        ResolutionDetails {
            value: map(self.value),
            variant: self.variant,
            reason: self.reason,
            flag_metadata: self.flag_metadata,
        }
    }
}

fn bounded_sdk_object(
    object: open_feature::StructValue,
) -> Result<FlagObject, open_feature::EvaluationError> {
    if object.fields.len() > MAX_FLAG_OBJECT_FIELDS {
        return Err(invalid_sdk_response());
    }
    let mut fields = Vec::with_capacity(object.fields.len());
    for (key, value) in object.fields {
        let value = match value {
            open_feature::Value::Bool(value) => FlagValue::boolean(value),
            open_feature::Value::Int(value) => FlagValue::integer(value),
            open_feature::Value::Float(value) => {
                FlagValue::float(value).map_err(|_| invalid_sdk_response())?
            }
            open_feature::Value::String(value) => {
                FlagValue::string(FlagString::new(value).map_err(|_| invalid_sdk_response())?)
            }
            open_feature::Value::Array(_) | open_feature::Value::Struct(_) => {
                return Err(invalid_sdk_response());
            }
        };
        fields.push((key, value));
    }
    FlagObject::new(fields).map_err(|_| invalid_sdk_response())
}

fn invalid_sdk_response() -> open_feature::EvaluationError {
    open_feature::EvaluationError {
        code: open_feature::EvaluationErrorCode::TypeMismatch,
        message: None,
    }
}
fn map_sdk_details(
    details: ResolutionDetails<FlagValue>,
) -> Result<ProviderEvaluation, ProviderError> {
    let variant = details
        .variant
        .map(Variant::new)
        .transpose()
        .map_err(|_| ProviderError::InvalidResponse)?;
    let reason = match details.reason {
        Some(OpenFeatureReason::Static) => ProviderReason::Static,
        Some(OpenFeatureReason::TargetingMatch) => ProviderReason::TargetingMatch,
        Some(OpenFeatureReason::Split) => ProviderReason::Split,
        Some(OpenFeatureReason::Disabled) => ProviderReason::Disabled,
        Some(
            OpenFeatureReason::Default
            | OpenFeatureReason::Cached
            | OpenFeatureReason::Unknown
            | OpenFeatureReason::Error
            | OpenFeatureReason::Other(_),
        )
        | None => ProviderReason::Unknown,
    };
    Ok(ProviderEvaluation {
        value: details.value,
        variant,
        reason,
    })
}

fn map_sdk_error(error: &open_feature::EvaluationError) -> ProviderError {
    use open_feature::EvaluationErrorCode;

    match &error.code {
        EvaluationErrorCode::ProviderNotReady | EvaluationErrorCode::General(_) => {
            ProviderError::Unavailable
        }
        EvaluationErrorCode::FlagNotFound => ProviderError::NotFound,
        EvaluationErrorCode::TargetingKeyMissing | EvaluationErrorCode::InvalidContext => {
            ProviderError::ContextRejected
        }
        EvaluationErrorCode::ParseError | EvaluationErrorCode::TypeMismatch => {
            ProviderError::InvalidResponse
        }
    }
}
