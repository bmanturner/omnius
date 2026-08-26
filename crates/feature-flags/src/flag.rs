use std::{collections::BTreeMap, fmt, str::FromStr};

use thiserror::Error;
use time::Date;

/// Maximum encoded flag-key length.
pub const MAX_FLAG_KEY_BYTES: usize = 128;
/// Maximum encoded string flag value length.
pub const MAX_FLAG_STRING_BYTES: usize = 1_024;
/// Maximum temporary-flag owner length.
pub const MAX_FLAG_OWNER_BYTES: usize = 64;
/// Maximum fields in one structured flag value.
pub const MAX_FLAG_OBJECT_FIELDS: usize = 16;
/// Maximum aggregate encoded structured flag size.
pub const MAX_FLAG_OBJECT_BYTES: usize = 4_096;
/// Maximum encoded structured flag field-name length.
pub const MAX_FLAG_OBJECT_KEY_BYTES: usize = 64;

const RESERVED_NAMESPACES: &[&str] = &[
    "acl",
    "auth",
    "authn",
    "authorization",
    "authz",
    "capabilities",
    "capability",
    "entitlement",
    "entitlements",
    "migration",
    "migrations",
    "permission",
    "permissions",
    "policy",
    "schema",
    "security",
];
fn is_reserved_namespace(segment: &str) -> bool {
    RESERVED_NAMESPACES
        .iter()
        .any(|namespace| segment.starts_with(namespace))
}

/// Why application product behavior may consult a flag.
///
/// Authorization, permissions, entitlements, capabilities, migrations, and schema compatibility
/// deliberately have no variant in this type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlagPurpose {
    /// Gradually release product behavior.
    ProductRollout,
    /// Assign product experiment behavior.
    Experiment,
    /// Vary non-security-sensitive user experience.
    UserExperience,
    /// Tune product operation without changing security or wire/storage compatibility.
    OperationalTuning,
}

impl FlagPurpose {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::ProductRollout => "product_rollout",
            Self::Experiment => "experiment",
            Self::UserExperience => "user_experience",
            Self::OperationalTuning => "operational_tuning",
        }
    }
}

impl FromStr for FlagPurpose {
    type Err = FlagPurposeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "product_rollout" => Ok(Self::ProductRollout),
            "experiment" => Ok(Self::Experiment),
            "user_experience" => Ok(Self::UserExperience),
            "operational_tuning" => Ok(Self::OperationalTuning),
            _ => Err(FlagPurposeError),
        }
    }
}

/// A purpose is not one of the closed product-only purposes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("flag purpose is not an allowed product purpose")]
pub struct FlagPurposeError;

/// A flag key violated its syntax, length, or reserved-namespace policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FlagKeyError {
    /// Keys must contain at least one byte.
    #[error("flag key must not be empty")]
    Empty,
    /// Keys have a fixed encoded length limit.
    #[error("flag key exceeds 128 bytes")]
    TooLong,
    /// Keys use lowercase ASCII dot-separated namespaces.
    #[error("flag key has invalid syntax")]
    InvalidSyntax,
    /// Security, authorization, capability, entitlement, migration, and schema namespaces are
    /// never feature-flag namespaces.
    #[error("flag key uses a reserved security or compatibility namespace")]
    ReservedNamespace,
}

/// A validated, bounded product feature-flag key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlagKey(String);

impl FlagKey {
    /// Validates and owns a dot-separated product feature-flag key.
    ///
    /// Every segment starts with a lowercase ASCII letter and contains only lowercase letters,
    /// digits, `_`, and `-`. Reserved namespaces are rejected in every segment so moving a
    /// security purpose below a product prefix cannot bypass the policy.
    ///
    /// # Errors
    ///
    /// Returns [`FlagKeyError`] when the key is empty, oversized, malformed, or reserved.
    pub fn new(value: impl Into<String>) -> Result<Self, FlagKeyError> {
        let value = value.into();
        if value.is_empty() {
            return Err(FlagKeyError::Empty);
        }
        if value.len() > MAX_FLAG_KEY_BYTES {
            return Err(FlagKeyError::TooLong);
        }

        for segment in value.split('.') {
            let Some(first) = segment.as_bytes().first().copied() else {
                return Err(FlagKeyError::InvalidSyntax);
            };
            if !first.is_ascii_lowercase()
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
            {
                return Err(FlagKeyError::InvalidSyntax);
            }
            if is_reserved_namespace(segment) {
                return Err(FlagKeyError::ReservedNamespace);
            }
        }
        Ok(Self(value))
    }

    /// Returns the validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FlagKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FlagKey").field(&self.0).finish()
    }
}

impl fmt::Display for FlagKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for FlagKey {
    type Err = FlagKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A string flag default or provider value was empty or oversized.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FlagStringError {
    /// Strings must be non-empty to avoid ambiguous provider defaults.
    #[error("string flag value must not be empty")]
    Empty,
    /// Strings have a fixed encoded size limit.
    #[error("string flag value exceeds 1024 bytes")]
    TooLong,
    /// Control characters cannot cross the feature-flag boundary.
    #[error("string flag value contains a control character")]
    ControlCharacter,
}

/// A non-empty, bounded UTF-8 feature-flag string.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlagString(String);

impl FlagString {
    /// Validates and owns a string flag value.
    ///
    /// # Errors
    ///
    /// Returns [`FlagStringError`] for empty, oversized, or control-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, FlagStringError> {
        let value = value.into();
        if value.is_empty() {
            return Err(FlagStringError::Empty);
        }
        if value.len() > MAX_FLAG_STRING_BYTES {
            return Err(FlagStringError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(FlagStringError::ControlCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the validated value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FlagString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FlagString")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// A structured flag violated its field or aggregate bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FlagObjectError {
    /// Structured field names must be non-empty.
    #[error("structured flag field name must not be empty")]
    EmptyKey,
    /// Structured field names have a fixed length limit.
    #[error("structured flag field name exceeds 64 bytes")]
    KeyTooLong,
    /// Structured field names use lowercase portable ASCII.
    #[error("structured flag field name has invalid syntax")]
    InvalidKey,
    /// Secret-bearing fields never cross the feature-flag boundary.
    #[error("structured flag field name is reserved for secret data")]
    SensitiveKey,
    /// Duplicate structured fields are rejected.
    #[error("structured flag contains a duplicate field")]
    DuplicateKey,
    /// Structured values have a fixed field-count limit.
    #[error("structured flag exceeds 16 fields")]
    TooManyFields,
    /// Structured values have a fixed aggregate encoded-size limit.
    #[error("structured flag exceeds 4096 bytes")]
    AggregateTooLarge,
    /// Arrays and nested structures are outside the bounded application contract.
    #[error("structured flag values must be flat scalars")]
    NestedValue,
}

/// A bounded flat structured feature-flag value.
///
/// Fields contain only the same bounded scalar [`FlagValue`] variants. Arrays, nested objects,
/// secret-bearing field names, and provider metadata are rejected.
#[derive(Clone, PartialEq)]
pub struct FlagObject {
    fields: BTreeMap<String, FlagValue>,
    encoded_len: usize,
}

impl FlagObject {
    /// Validates and owns a flat structured value.
    ///
    /// # Errors
    ///
    /// Returns [`FlagObjectError`] for unsafe keys, duplicates, nested values, or count/size
    /// violations.
    pub fn new<K, I>(fields: I) -> Result<Self, FlagObjectError>
    where
        K: Into<String>,
        I: IntoIterator<Item = (K, FlagValue)>,
    {
        let mut object = Self {
            fields: BTreeMap::new(),
            encoded_len: 0,
        };
        for (key, value) in fields {
            if object.fields.len() >= MAX_FLAG_OBJECT_FIELDS {
                return Err(FlagObjectError::TooManyFields);
            }
            let key = key.into();
            validate_object_key(&key)?;
            if value.kind() == FlagValueKind::Object {
                return Err(FlagObjectError::NestedValue);
            }
            let next_len = object
                .encoded_len
                .saturating_add(key.len())
                .saturating_add(value.encoded_len());
            if next_len > MAX_FLAG_OBJECT_BYTES {
                return Err(FlagObjectError::AggregateTooLarge);
            }
            if object.fields.insert(key, value).is_some() {
                return Err(FlagObjectError::DuplicateKey);
            }
            object.encoded_len = next_len;
        }
        Ok(object)
    }

    /// Creates an empty structured value.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            fields: BTreeMap::new(),
            encoded_len: 0,
        }
    }

    /// Returns one validated field value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&FlagValue> {
        self.fields.get(key)
    }

    /// Iterates validated fields in stable name order.
    #[must_use]
    pub fn fields(&self) -> impl ExactSizeIterator<Item = (&str, &FlagValue)> {
        self.fields.iter().map(|(key, value)| (key.as_str(), value))
    }

    /// Returns the number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns whether the structure has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Returns the precomputed aggregate encoded size.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

impl fmt::Debug for FlagObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlagObject")
            .field(
                "fields",
                &format_args!("[REDACTED; {} fields]", self.fields.len()),
            )
            .field("encoded_len", &self.encoded_len)
            .finish()
    }
}

fn validate_object_key(key: &str) -> Result<(), FlagObjectError> {
    if key.is_empty() {
        return Err(FlagObjectError::EmptyKey);
    }
    if key.len() > MAX_FLAG_OBJECT_KEY_BYTES {
        return Err(FlagObjectError::KeyTooLong);
    }
    let Some(first) = key.as_bytes().first().copied() else {
        return Err(FlagObjectError::EmptyKey);
    };
    if !first.is_ascii_lowercase()
        || !key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(FlagObjectError::InvalidKey);
    }
    let contains_sensitive_token = key.split(['_', '-']).any(|part| {
        matches!(
            part,
            "apikey"
                | "accesskey"
                | "clientsecret"
                | "credential"
                | "credentials"
                | "password"
                | "privatekey"
                | "secret"
                | "secretkey"
                | "token"
        )
    });
    let is_sensitive_compound = [
        "access_key",
        "api_key",
        "client_key",
        "encryption_key",
        "private_key",
        "secret_key",
        "signing_key",
    ]
    .iter()
    .any(|sensitive| normalized_object_key_eq(key, sensitive));
    if contains_sensitive_token || is_sensitive_compound {
        return Err(FlagObjectError::SensitiveKey);
    }
    Ok(())
}

fn normalized_object_key_eq(key: &str, expected: &str) -> bool {
    key.bytes()
        .map(|byte| if byte == b'-' { b'_' } else { byte })
        .eq(expected.bytes())
}

/// The closed set of supported, bounded flag value types.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlagValueKind {
    /// A boolean value.
    Boolean,
    /// A signed 64-bit integer value.
    Integer,
    /// A finite 64-bit floating-point value.
    Float,
    /// A bounded UTF-8 string value.
    String,
    /// A bounded flat structured value.
    Object,
}

impl FlagValueKind {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Float => "float",
            Self::String => "string",
            Self::Object => "object",
        }
    }
}

#[derive(Clone, PartialEq)]
enum FlagValueInner {
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(FlagString),
    Object(FlagObject),
}

/// A validated provider value whose representation is bounded by its type.
#[derive(Clone, PartialEq)]
pub struct FlagValue(FlagValueInner);

impl FlagValue {
    /// Creates a boolean provider value.
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self(FlagValueInner::Boolean(value))
    }

    /// Creates an integer provider value.
    #[must_use]
    pub const fn integer(value: i64) -> Self {
        Self(FlagValueInner::Integer(value))
    }

    /// Creates a finite floating-point provider value.
    ///
    /// # Errors
    ///
    /// Returns [`FlagValueError::NonFiniteFloat`] for `NaN` and infinities.
    pub fn float(value: f64) -> Result<Self, FlagValueError> {
        if value.is_finite() {
            Ok(Self(FlagValueInner::Float(value)))
        } else {
            Err(FlagValueError::NonFiniteFloat)
        }
    }

    /// Creates a string provider value from an already bounded string.
    #[must_use]
    pub const fn string(value: FlagString) -> Self {
        Self(FlagValueInner::String(value))
    }
    /// Creates a bounded flat structured provider value.
    #[must_use]
    pub const fn object(value: FlagObject) -> Self {
        Self(FlagValueInner::Object(value))
    }

    /// Returns the value's closed type.
    #[must_use]
    pub const fn kind(&self) -> FlagValueKind {
        match &self.0 {
            FlagValueInner::Boolean(_) => FlagValueKind::Boolean,
            FlagValueInner::Integer(_) => FlagValueKind::Integer,
            FlagValueInner::Float(_) => FlagValueKind::Float,
            FlagValueInner::String(_) => FlagValueKind::String,
            FlagValueInner::Object(_) => FlagValueKind::Object,
        }
    }
    /// Returns the boolean when the value has boolean kind.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match &self.0 {
            FlagValueInner::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the integer when the value has integer kind.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match &self.0 {
            FlagValueInner::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the finite float when the value has float kind.
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        match &self.0 {
            FlagValueInner::Float(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the bounded string when the value has string kind.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match &self.0 {
            FlagValueInner::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    /// Returns the bounded flat structure when the value has object kind.
    #[must_use]
    pub const fn as_object(&self) -> Option<&FlagObject> {
        match &self.0 {
            FlagValueInner::Object(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) const fn encoded_len(&self) -> usize {
        match &self.0 {
            FlagValueInner::Boolean(_) => 1,
            FlagValueInner::Integer(_) | FlagValueInner::Float(_) => std::mem::size_of::<i64>(),
            FlagValueInner::String(value) => value.0.len(),
            FlagValueInner::Object(value) => value.encoded_len(),
        }
    }
}

impl fmt::Debug for FlagValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FlagValue")
            .field(&format_args!("[REDACTED; kind={:?}]", self.kind()))
            .finish()
    }
}

/// A flag value cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FlagValueError {
    /// Floating-point flags must be finite.
    #[error("floating-point flag value must be finite")]
    NonFiniteFloat,
}

mod private {
    pub trait Sealed {}

    impl Sealed for bool {}
    impl Sealed for i64 {}
    impl Sealed for f64 {}
    impl Sealed for super::FlagString {}
    impl Sealed for super::FlagObject {}
}

/// A statically typed value accepted by [`Flag`].
///
/// This trait is sealed; supported values are `bool`, `i64`, finite `f64`, [`FlagString`], and
/// [`FlagObject`].
pub trait FlagValueType: private::Sealed + Clone + Send + Sync + 'static {
    /// The corresponding closed provider value kind.
    const KIND: FlagValueKind;

    #[doc(hidden)]
    fn validate(&self) -> Result<(), FlagValueError>;
    #[doc(hidden)]
    fn into_untyped(self) -> FlagValue;
    #[doc(hidden)]
    fn from_untyped(value: &FlagValue) -> Option<Self>;
}

impl FlagValueType for bool {
    const KIND: FlagValueKind = FlagValueKind::Boolean;

    fn validate(&self) -> Result<(), FlagValueError> {
        Ok(())
    }

    fn into_untyped(self) -> FlagValue {
        FlagValue::boolean(self)
    }

    fn from_untyped(value: &FlagValue) -> Option<Self> {
        let FlagValueInner::Boolean(value) = &value.0 else {
            return None;
        };
        Some(*value)
    }
}

impl FlagValueType for i64 {
    const KIND: FlagValueKind = FlagValueKind::Integer;

    fn validate(&self) -> Result<(), FlagValueError> {
        Ok(())
    }

    fn into_untyped(self) -> FlagValue {
        FlagValue::integer(self)
    }

    fn from_untyped(value: &FlagValue) -> Option<Self> {
        let FlagValueInner::Integer(value) = &value.0 else {
            return None;
        };
        Some(*value)
    }
}

impl FlagValueType for f64 {
    const KIND: FlagValueKind = FlagValueKind::Float;

    fn validate(&self) -> Result<(), FlagValueError> {
        if self.is_finite() {
            Ok(())
        } else {
            Err(FlagValueError::NonFiniteFloat)
        }
    }

    fn into_untyped(self) -> FlagValue {
        FlagValue(FlagValueInner::Float(self))
    }

    fn from_untyped(value: &FlagValue) -> Option<Self> {
        let FlagValueInner::Float(value) = &value.0 else {
            return None;
        };
        Some(*value)
    }
}

impl FlagValueType for FlagString {
    const KIND: FlagValueKind = FlagValueKind::String;

    fn validate(&self) -> Result<(), FlagValueError> {
        Ok(())
    }

    fn into_untyped(self) -> FlagValue {
        FlagValue::string(self)
    }

    fn from_untyped(value: &FlagValue) -> Option<Self> {
        let FlagValueInner::String(value) = &value.0 else {
            return None;
        };
        Some(value.clone())
    }
}

impl FlagValueType for FlagObject {
    const KIND: FlagValueKind = FlagValueKind::Object;

    fn validate(&self) -> Result<(), FlagValueError> {
        Ok(())
    }

    fn into_untyped(self) -> FlagValue {
        FlagValue::object(self)
    }

    fn from_untyped(value: &FlagValue) -> Option<Self> {
        let FlagValueInner::Object(value) = &value.0 else {
            return None;
        };
        Some(value.clone())
    }
}

/// A temporary-flag owner was empty, oversized, or malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FlagOwnerError {
    /// An owner is mandatory for a temporary flag.
    #[error("temporary flag owner must not be empty")]
    Empty,
    /// Owners have a fixed encoded size limit.
    #[error("temporary flag owner exceeds 64 bytes")]
    TooLong,
    /// Owner identifiers use a portable, log-safe character set.
    #[error("temporary flag owner contains a forbidden character")]
    InvalidCharacter,
}

/// Bounded accountable owner metadata for a temporary flag.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlagOwner(String);

impl FlagOwner {
    /// Validates and owns a team or maintainer identifier.
    ///
    /// # Errors
    ///
    /// Returns [`FlagOwnerError`] for empty, oversized, or non-portable values.
    pub fn new(value: impl Into<String>) -> Result<Self, FlagOwnerError> {
        let value = value.into();
        if value.is_empty() {
            return Err(FlagOwnerError::Empty);
        }
        if value.len() > MAX_FLAG_OWNER_BYTES {
            return Err(FlagOwnerError::TooLong);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b'@')
        }) {
            return Err(FlagOwnerError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the accountable owner identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lifecycle metadata required by a flag definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlagLifecycle {
    /// Long-lived product configuration.
    Permanent,
    /// A temporary flag with accountable removal metadata.
    Temporary {
        /// Team or maintainer accountable for removal.
        owner: FlagOwner,
        /// Date by which the definition and both behavior branches must be removed.
        remove_after: Date,
    },
}

/// A typed flag definition was invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FlagDefinitionError {
    /// The key is unsafe or malformed.
    #[error(transparent)]
    Key(#[from] FlagKeyError),
    /// The default value cannot be represented safely.
    #[error(transparent)]
    Value(#[from] FlagValueError),
    /// Temporary owner metadata is unsafe or malformed.
    #[error(transparent)]
    Owner(#[from] FlagOwnerError),
}

/// A typed product feature flag with an explicit safe default and lifecycle.
#[derive(Clone)]
pub struct Flag<T: FlagValueType> {
    key: FlagKey,
    default: T,
    purpose: FlagPurpose,
    lifecycle: FlagLifecycle,
}

impl<T: FlagValueType> Flag<T> {
    /// Defines a permanent product flag.
    ///
    /// # Errors
    ///
    /// Returns [`FlagDefinitionError`] when the key or default violates the boundary.
    pub fn permanent(
        key: impl Into<String>,
        default: T,
        purpose: FlagPurpose,
    ) -> Result<Self, FlagDefinitionError> {
        default.validate()?;
        Ok(Self {
            key: FlagKey::new(key)?,
            default,
            purpose,
            lifecycle: FlagLifecycle::Permanent,
        })
    }

    /// Defines a temporary product flag with mandatory owner and removal date.
    ///
    /// # Errors
    ///
    /// Returns [`FlagDefinitionError`] when the key, default, or owner violates the boundary.
    pub fn temporary(
        key: impl Into<String>,
        default: T,
        purpose: FlagPurpose,
        owner: impl Into<String>,
        remove_after: Date,
    ) -> Result<Self, FlagDefinitionError> {
        default.validate()?;
        Ok(Self {
            key: FlagKey::new(key)?,
            default,
            purpose,
            lifecycle: FlagLifecycle::Temporary {
                owner: FlagOwner::new(owner)?,
                remove_after,
            },
        })
    }

    /// Returns the bounded provider key.
    #[must_use]
    pub const fn key(&self) -> &FlagKey {
        &self.key
    }

    /// Returns the safe failure default.
    #[must_use]
    pub const fn default_value(&self) -> &T {
        &self.default
    }

    /// Returns the product-only use classification.
    #[must_use]
    pub const fn purpose(&self) -> FlagPurpose {
        self.purpose
    }

    /// Returns permanent or accountable temporary lifecycle metadata.
    #[must_use]
    pub const fn lifecycle(&self) -> &FlagLifecycle {
        &self.lifecycle
    }
}

impl<T: FlagValueType> fmt::Debug for Flag<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Flag")
            .field("key", &self.key)
            .field("value_kind", &T::KIND)
            .field("default", &"[REDACTED]")
            .field("purpose", &self.purpose)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}
