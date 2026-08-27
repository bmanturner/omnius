use std::{collections::BTreeMap, fmt, str::FromStr};

use omnius_auth_core::{Principal, PrincipalKind, SubjectId, TenantId};
use thiserror::Error;

/// Maximum custom fields in one evaluation context.
pub const MAX_CONTEXT_ATTRIBUTES: usize = 6;
/// Maximum aggregate encoded context size, including canonical identity fields.
pub const MAX_CONTEXT_BYTES: usize = 1_024;
/// Maximum encoded size of one string context value.
pub const MAX_CONTEXT_VALUE_BYTES: usize = 256;

/// The closed application-owned allowlist of provider targeting attributes.
///
/// Subject and tenant identifiers are not variants because they can only be populated from the
/// canonical [`Principal`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContextAttribute {
    /// Deployment environment, populated by [`EvaluationContext::new`].
    Environment,
    /// Application-owned product cohort.
    Cohort,
    /// Validated locale identifier supplied by the application.
    Locale,
    /// Deployed application version.
    AppVersion,
    /// Coarse deployment region.
    Region,
    /// Coarse device class, never a user-agent or fingerprint.
    DeviceClass,
}

impl ContextAttribute {
    /// Returns the stable `OpenFeature` custom-field name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Cohort => "cohort",
            Self::Locale => "locale",
            Self::AppVersion => "app_version",
            Self::Region => "region",
            Self::DeviceClass => "device_class",
        }
    }
}

impl FromStr for ContextAttribute {
    type Err = ContextError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "environment" => Ok(Self::Environment),
            "cohort" => Ok(Self::Cohort),
            "locale" => Ok(Self::Locale),
            "app_version" => Ok(Self::AppVersion),
            "region" => Ok(Self::Region),
            "device_class" => Ok(Self::DeviceClass),
            _ => Err(ContextError::AttributeNotAllowed),
        }
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum ContextValueInner {
    String(String),
    Boolean(bool),
    Integer(i64),
}

/// A bounded scalar targeting value.
///
/// Arbitrary structures, arrays, timestamps, and floating-point values are deliberately excluded.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ContextValue(ContextValueInner);

impl ContextValue {
    /// Creates a bounded, non-empty UTF-8 string targeting value.
    ///
    /// # Errors
    ///
    /// Returns [`ContextValueError`] for empty, oversized, or control-bearing values.
    pub fn string(value: impl Into<String>) -> Result<Self, ContextValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ContextValueError::Empty);
        }
        if value.len() > MAX_CONTEXT_VALUE_BYTES {
            return Err(ContextValueError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(ContextValueError::ControlCharacter);
        }
        Ok(Self(ContextValueInner::String(value)))
    }

    /// Creates a boolean targeting value.
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self(ContextValueInner::Boolean(value))
    }

    /// Creates an integer targeting value.
    #[must_use]
    pub const fn integer(value: i64) -> Self {
        Self(ContextValueInner::Integer(value))
    }
    /// Returns the string value when this is a string targeting fact.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match &self.0 {
            ContextValueInner::String(value) => Some(value),
            ContextValueInner::Boolean(_) | ContextValueInner::Integer(_) => None,
        }
    }

    /// Returns the boolean value when this is a boolean targeting fact.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match &self.0 {
            ContextValueInner::Boolean(value) => Some(*value),
            ContextValueInner::String(_) | ContextValueInner::Integer(_) => None,
        }
    }

    /// Returns the integer value when this is an integer targeting fact.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match &self.0 {
            ContextValueInner::Integer(value) => Some(*value),
            ContextValueInner::String(_) | ContextValueInner::Boolean(_) => None,
        }
    }

    pub(crate) const fn encoded_len(&self) -> usize {
        match &self.0 {
            ContextValueInner::String(value) => value.len(),
            ContextValueInner::Boolean(_) => 1,
            ContextValueInner::Integer(_) => std::mem::size_of::<i64>(),
        }
    }

    pub(crate) fn as_sdk_value(&self) -> SdkContextValue<'_> {
        match &self.0 {
            ContextValueInner::String(value) => SdkContextValue::String(value),
            ContextValueInner::Boolean(value) => SdkContextValue::Boolean(*value),
            ContextValueInner::Integer(value) => SdkContextValue::Integer(*value),
        }
    }
}

impl fmt::Debug for ContextValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContextValue")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// A context string value was unsafe or unbounded.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContextValueError {
    /// Empty values are not valid targeting facts.
    #[error("context string value must not be empty")]
    Empty,
    /// Individual context values have a fixed size limit.
    #[error("context string value exceeds 256 bytes")]
    TooLong,
    /// Control characters cannot cross the provider boundary.
    #[error("context string value contains a control character")]
    ControlCharacter,
}

/// A context violated the allowlist, uniqueness, or aggregate bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContextError {
    /// A raw field name was not on the closed allowlist.
    #[error("evaluation context attribute is not allowed")]
    AttributeNotAllowed,
    /// Each targeting attribute may occur at most once.
    #[error("evaluation context contains a duplicate attribute")]
    DuplicateAttribute,
    /// The context contains too many custom fields.
    #[error("evaluation context exceeds 6 custom attributes")]
    TooManyAttributes,
    /// The complete context exceeds its fixed encoded-size limit.
    #[error("evaluation context exceeds 1024 bytes")]
    AggregateTooLarge,
    /// The required environment value was malformed.
    #[error(transparent)]
    Value(#[from] ContextValueError),
}

/// The canonical principal facts and bounded allowlisted product targeting context.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EvaluationContext {
    subject_id: Option<SubjectId>,
    tenant_id: Option<TenantId>,
    principal_kind: Option<PrincipalKind>,
    attributes: BTreeMap<ContextAttribute, ContextValue>,
    encoded_len: usize,
}

impl EvaluationContext {
    /// Creates a bounded context for an anonymous or canonical authenticated principal.
    ///
    /// Only the canonical subject, tenant, and principal kind are copied from `principal`; scopes,
    /// authentication method, and assurance are authorization facts and never provider context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when `environment` is invalid or the aggregate limit is exceeded.
    pub fn new(
        environment: impl Into<String>,
        principal: Option<&Principal>,
    ) -> Result<Self, ContextError> {
        let environment = ContextValue::string(environment)?;
        let (subject_id, tenant_id, principal_kind) =
            principal.map_or((None, None, None), |principal| {
                (
                    Some(principal.subject_id),
                    principal.tenant_id,
                    Some(principal.kind),
                )
            });
        let identity_len = subject_id.map_or(0, |_| "targeting_key".len() + 36)
            + tenant_id.map_or(0, |_| "tenant_id".len() + 36)
            + principal_kind.map_or(0, |_| "principal_kind".len() + 16);
        let mut context = Self {
            subject_id,
            tenant_id,
            principal_kind,
            attributes: BTreeMap::new(),
            encoded_len: identity_len,
        };
        context.insert(ContextAttribute::Environment, environment)?;
        Ok(context)
    }

    /// Adds one typed allowlisted targeting attribute.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] for duplicates or count/aggregate bound violations.
    pub fn with_attribute(
        mut self,
        attribute: ContextAttribute,
        value: ContextValue,
    ) -> Result<Self, ContextError> {
        self.insert(attribute, value)?;
        Ok(self)
    }

    /// Validates a raw attribute name against the same closed allowlist before insertion.
    ///
    /// This method is intended for configuration and transport adapters. Prefer
    /// [`Self::with_attribute`] in application code.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::AttributeNotAllowed`] for every unknown name and the regular
    /// duplicate/count/aggregate errors for an allowed field.
    pub fn with_raw_attribute(
        self,
        attribute: &str,
        value: ContextValue,
    ) -> Result<Self, ContextError> {
        self.with_attribute(attribute.parse()?, value)
    }

    fn insert(
        &mut self,
        attribute: ContextAttribute,
        value: ContextValue,
    ) -> Result<(), ContextError> {
        if self.attributes.contains_key(&attribute) {
            return Err(ContextError::DuplicateAttribute);
        }
        if self.attributes.len() >= MAX_CONTEXT_ATTRIBUTES {
            return Err(ContextError::TooManyAttributes);
        }
        let added_len = attribute.as_str().len().saturating_add(value.encoded_len());
        let next_len = self.encoded_len.saturating_add(added_len);
        if next_len > MAX_CONTEXT_BYTES {
            return Err(ContextError::AggregateTooLarge);
        }
        self.attributes.insert(attribute, value);
        self.encoded_len = next_len;
        Ok(())
    }

    /// Returns the canonical subject identifier, when authenticated.
    #[must_use]
    pub const fn subject_id(&self) -> Option<SubjectId> {
        self.subject_id
    }

    /// Returns the canonical tenant identifier, when established by authentication.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    /// Returns the canonical subject class, when authenticated.
    #[must_use]
    pub const fn principal_kind(&self) -> Option<PrincipalKind> {
        self.principal_kind
    }

    /// Returns one allowlisted targeting value.
    #[must_use]
    pub fn get(&self, attribute: ContextAttribute) -> Option<&ContextValue> {
        self.attributes.get(&attribute)
    }

    /// Iterates the bounded custom attributes in stable key order.
    #[must_use]
    pub fn attributes(&self) -> impl ExactSizeIterator<Item = (ContextAttribute, &ContextValue)> {
        self.attributes.iter().map(|(key, value)| (*key, value))
    }

    /// Returns the precomputed aggregate encoded size.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

impl fmt::Debug for EvaluationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvaluationContext")
            .field("subject_id", &self.subject_id.map(|_| "[REDACTED]"))
            .field("tenant_id", &self.tenant_id.map(|_| "[REDACTED]"))
            .field("principal_kind", &self.principal_kind)
            .field(
                "attributes",
                &format_args!("[REDACTED; {} fields]", self.attributes.len()),
            )
            .field("encoded_len", &self.encoded_len)
            .finish()
    }
}

pub(crate) enum SdkContextValue<'value> {
    String(&'value str),
    Boolean(bool),
    Integer(i64),
}
