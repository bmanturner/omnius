use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_IDENTIFIER_BYTES: usize = 128;
const REDACTED: &str = "[redacted]";

macro_rules! bounded_id {
    ($name:ident, $docs:literal) => {
        #[doc = $docs]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses a non-empty bounded identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError`] for an empty, oversized, or unsafe identifier.
            pub fn new(value: &str) -> Result<Self, IdentifierError> {
                validate_identifier(value)?;
                Ok(Self(value.to_owned()))
            }

            /// Borrows the canonical identifier for persistence and equality.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(&value).map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(REDACTED)
            }
        }
    };
}

bounded_id!(TenantId, "An opaque tenant accounting boundary.");
bounded_id!(
    PrincipalId,
    "An opaque authenticated principal budget dimension."
);
bounded_id!(ApiKeyId, "An opaque API-key budget dimension.");
bounded_id!(ProviderId, "An opaque provider budget dimension.");
bounded_id!(ModelId, "An opaque model budget dimension.");
bounded_id!(RouteId, "An opaque versioned route budget dimension.");
bounded_id!(ToolId, "An opaque tool budget dimension.");
bounded_id!(OperationId, "An opaque operation budget dimension.");
bounded_id!(JobId, "An opaque durable-job budget dimension.");
bounded_id!(ReservationId, "An opaque reservation identifier.");
bounded_id!(
    IdempotencyKey,
    "A bounded tenant-scoped reservation idempotency key."
);

/// A 256-bit fingerprint of all dispatch-affecting reservation input.
#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RequestFingerprint([u8; 32]);

impl RequestFingerprint {
    /// Creates a fingerprint from an already computed digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the digest bytes for persistence.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestFingerprint([redacted])")
    }
}

/// Monotonic compare-and-set version for one reservation.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct LedgerVersion(u64);

impl LedgerVersion {
    /// Initial persisted version.
    pub const INITIAL: Self = Self(0);

    /// Creates a version from persisted state.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the integer version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next exact version.
    ///
    /// # Errors
    ///
    /// Returns [`VersionOverflow`] when no version remains.
    pub const fn checked_next(self) -> Result<Self, VersionOverflow> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(VersionOverflow),
        }
    }
}

/// A reservation version cannot advance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("usage ledger version exhausted")]
pub struct VersionOverflow;

/// The dimensions present in a scope without any sensitive identifier values.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "a value-free audit presence bitmap must expose independent dimensions"
)]
pub struct DimensionSet {
    principal: bool,
    api_key: bool,
    provider: bool,
    model: bool,
    route: bool,
    tool: bool,
    operation: bool,
    job: bool,
}

impl DimensionSet {
    /// Returns whether the scope includes a principal.
    #[must_use]
    pub const fn has_principal(self) -> bool {
        self.principal
    }

    /// Returns whether the scope includes an API key.
    #[must_use]
    pub const fn has_api_key(self) -> bool {
        self.api_key
    }

    /// Returns whether the scope includes a provider.
    #[must_use]
    pub const fn has_provider(self) -> bool {
        self.provider
    }

    /// Returns whether the scope includes a model.
    #[must_use]
    pub const fn has_model(self) -> bool {
        self.model
    }

    /// Returns whether the scope includes a route.
    #[must_use]
    pub const fn has_route(self) -> bool {
        self.route
    }

    /// Returns whether the scope includes a tool.
    #[must_use]
    pub const fn has_tool(self) -> bool {
        self.tool
    }

    /// Returns whether the scope includes an operation.
    #[must_use]
    pub const fn has_operation(self) -> bool {
        self.operation
    }

    /// Returns whether the scope includes a job.
    #[must_use]
    pub const fn has_job(self) -> bool {
        self.job
    }
}

/// Tenant-owned budget dimensions attached to one dispatch.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetScope {
    tenant: TenantId,
    principal: Option<PrincipalId>,
    api_key: Option<ApiKeyId>,
    provider: Option<ProviderId>,
    model: Option<ModelId>,
    route: Option<RouteId>,
    tool: Option<ToolId>,
    operation: Option<OperationId>,
    job: Option<JobId>,
}

impl BudgetScope {
    /// Starts a scope at its mandatory tenant boundary.
    #[must_use]
    pub fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            principal: None,
            api_key: None,
            provider: None,
            model: None,
            route: None,
            tool: None,
            operation: None,
            job: None,
        }
    }

    /// Adds a principal dimension.
    #[must_use]
    pub fn with_principal(mut self, value: PrincipalId) -> Self {
        self.principal = Some(value);
        self
    }
    /// Adds an API-key dimension.
    #[must_use]
    pub fn with_api_key(mut self, value: ApiKeyId) -> Self {
        self.api_key = Some(value);
        self
    }

    /// Adds a provider dimension.
    #[must_use]
    pub fn with_provider(mut self, value: ProviderId) -> Self {
        self.provider = Some(value);
        self
    }

    /// Adds a model dimension.
    #[must_use]
    pub fn with_model(mut self, value: ModelId) -> Self {
        self.model = Some(value);
        self
    }

    /// Adds a versioned route dimension.
    #[must_use]
    pub fn with_route(mut self, value: RouteId) -> Self {
        self.route = Some(value);
        self
    }

    /// Adds a tool dimension.
    #[must_use]
    pub fn with_tool(mut self, value: ToolId) -> Self {
        self.tool = Some(value);
        self
    }
    /// Adds a generic operation dimension.
    #[must_use]
    pub fn with_operation(mut self, value: OperationId) -> Self {
        self.operation = Some(value);
        self
    }

    /// Adds a durable-job dimension.
    #[must_use]
    pub fn with_job(mut self, value: JobId) -> Self {
        self.job = Some(value);
        self
    }

    /// Borrows the mandatory tenant boundary.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Borrows the optional principal dimension.
    #[must_use]
    pub const fn principal(&self) -> Option<&PrincipalId> {
        self.principal.as_ref()
    }
    /// Borrows the optional API-key dimension.
    #[must_use]
    pub const fn api_key(&self) -> Option<&ApiKeyId> {
        self.api_key.as_ref()
    }

    /// Borrows the optional provider dimension.
    #[must_use]
    pub const fn provider(&self) -> Option<&ProviderId> {
        self.provider.as_ref()
    }

    /// Borrows the optional model dimension.
    #[must_use]
    pub const fn model(&self) -> Option<&ModelId> {
        self.model.as_ref()
    }

    /// Borrows the optional route dimension.
    #[must_use]
    pub const fn route(&self) -> Option<&RouteId> {
        self.route.as_ref()
    }

    /// Borrows the optional tool dimension.
    #[must_use]
    pub const fn tool(&self) -> Option<&ToolId> {
        self.tool.as_ref()
    }
    /// Borrows the optional operation dimension.
    #[must_use]
    pub const fn operation(&self) -> Option<&OperationId> {
        self.operation.as_ref()
    }

    /// Borrows the optional durable-job dimension.
    #[must_use]
    pub const fn job(&self) -> Option<&JobId> {
        self.job.as_ref()
    }

    /// Returns only the safe presence bitmap for audit and diagnostics.
    #[must_use]
    pub const fn dimensions(&self) -> DimensionSet {
        DimensionSet {
            principal: self.principal.is_some(),
            api_key: self.api_key.is_some(),
            provider: self.provider.is_some(),
            model: self.model.is_some(),
            route: self.route.is_some(),
            tool: self.tool.is_some(),
            operation: self.operation.is_some(),
            job: self.job.is_some(),
        }
    }

    pub(crate) fn contains_dimension(&self, dimension: crate::BudgetDimension) -> bool {
        match dimension {
            crate::BudgetDimension::Tenant => true,
            crate::BudgetDimension::Principal => self.principal.is_some(),
            crate::BudgetDimension::ApiKey => self.api_key.is_some(),
            crate::BudgetDimension::Provider => self.provider.is_some(),
            crate::BudgetDimension::Model => self.model.is_some(),
            crate::BudgetDimension::Route => self.route.is_some(),
            crate::BudgetDimension::Tool => self.tool.is_some(),
            crate::BudgetDimension::Operation => self.operation.is_some(),
            crate::BudgetDimension::Job => self.job.is_some(),
        }
    }

    /// Returns whether both scopes share the same tenant and selected dimension value.
    ///
    /// Repository adapters use this predicate to define the exact aggregate represented by a
    /// [`crate::BudgetPolicy`]. The compared values are never formatted.
    #[must_use]
    pub fn matches_dimension(&self, other: &Self, dimension: crate::BudgetDimension) -> bool {
        if self.tenant != other.tenant {
            return false;
        }
        match dimension {
            crate::BudgetDimension::Tenant => true,
            crate::BudgetDimension::Principal => self.principal == other.principal,
            crate::BudgetDimension::ApiKey => self.api_key == other.api_key,
            crate::BudgetDimension::Provider => self.provider == other.provider,
            crate::BudgetDimension::Model => self.model == other.model,
            crate::BudgetDimension::Route => self.route == other.route,
            crate::BudgetDimension::Tool => self.tool == other.tool,
            crate::BudgetDimension::Operation => self.operation == other.operation,
            crate::BudgetDimension::Job => self.job == other.job,
        }
    }
}

impl fmt::Debug for BudgetScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetScope")
            .field("tenant", &REDACTED)
            .field("dimensions", &self.dimensions())
            .finish()
    }
}

/// A bounded identifier was invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("identifier must be non-empty, bounded, and use the safe identifier alphabet")]
pub struct IdentifierError;

fn validate_identifier(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        })
    {
        return Err(IdentifierError);
    }
    Ok(())
}
