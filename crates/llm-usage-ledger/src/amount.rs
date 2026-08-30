use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An exact usage counter.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct UsageAmount(u64);

impl UsageAmount {
    /// Zero usage.
    pub const ZERO: Self = Self(0);
    /// One unit of usage.
    pub const ONE: Self = Self(1);
    /// The greatest representable usage amount.
    pub const MAX: Self = Self(u64::MAX);

    /// Creates an exact usage amount.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the exact integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds without wrapping or saturation.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when the exact result is not representable.
    pub const fn checked_add(self, other: Self) -> Result<Self, ArithmeticError> {
        match self.0.checked_add(other.0) {
            Some(value) => Ok(Self(value)),
            None => Err(ArithmeticError),
        }
    }

    /// Subtracts without wrapping or saturation.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when `other` is greater than this amount.
    pub const fn checked_sub(self, other: Self) -> Result<Self, ArithmeticError> {
        match self.0.checked_sub(other.0) {
            Some(value) => Ok(Self(value)),
            None => Err(ArithmeticError),
        }
    }
}

/// An exact non-negative monetary amount in application-defined microunits.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct CostMicrounits(u64);

impl CostMicrounits {
    /// Zero cost.
    pub const ZERO: Self = Self(0);
    /// The greatest representable exact cost.
    pub const MAX: Self = Self(u64::MAX);

    /// Creates an exact microunit cost.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the exact integer microunit value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds without wrapping or saturation.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when the exact result is not representable.
    pub const fn checked_add(self, other: Self) -> Result<Self, ArithmeticError> {
        match self.0.checked_add(other.0) {
            Some(value) => Ok(Self(value)),
            None => Err(ArithmeticError),
        }
    }

    /// Subtracts without wrapping or saturation.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when `other` is greater than this amount.
    pub const fn checked_sub(self, other: Self) -> Result<Self, ArithmeticError> {
        match self.0.checked_sub(other.0) {
            Some(value) => Ok(Self(value)),
            None => Err(ArithmeticError),
        }
    }
}

/// An exact signed usage adjustment.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct SignedUsageAmount(i128);

impl SignedUsageAmount {
    /// Returns the signed exact integer value.
    #[must_use]
    pub const fn get(self) -> i128 {
        self.0
    }

    fn between(current: UsageAmount, previous: UsageAmount) -> Self {
        Self(i128::from(current.get()) - i128::from(previous.get()))
    }
}

/// An exact signed cost adjustment in microunits.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(transparent)]
pub struct SignedCostMicrounits(i128);

impl SignedCostMicrounits {
    /// Returns the signed exact microunit value.
    #[must_use]
    pub const fn get(self) -> i128 {
        self.0
    }

    fn between(current: CostMicrounits, previous: CostMicrounits) -> Self {
        Self(i128::from(current.get()) - i128::from(previous.get()))
    }
}

/// Exact resource usage and cost for one attribution class.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageVector {
    requests: UsageAmount,
    concurrent_streams: UsageAmount,
    tokens: UsageAmount,
    units: UsageAmount,
    tool_calls: UsageAmount,
    media_bytes: UsageAmount,
    cost_microunits: CostMicrounits,
}

impl UsageVector {
    /// Creates an empty vector.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            requests: UsageAmount::ZERO,
            concurrent_streams: UsageAmount::ZERO,
            tokens: UsageAmount::ZERO,
            units: UsageAmount::ZERO,
            tool_calls: UsageAmount::ZERO,
            media_bytes: UsageAmount::ZERO,
            cost_microunits: CostMicrounits::ZERO,
        }
    }

    /// Sets the request count.
    #[must_use]
    pub const fn with_requests(mut self, value: UsageAmount) -> Self {
        self.requests = value;
        self
    }

    /// Sets the concurrent-stream count.
    #[must_use]
    pub const fn with_concurrent_streams(mut self, value: UsageAmount) -> Self {
        self.concurrent_streams = value;
        self
    }

    /// Sets the aggregate token count.
    #[must_use]
    pub const fn with_tokens(mut self, value: UsageAmount) -> Self {
        self.tokens = value;
        self
    }

    /// Sets provider-neutral non-token units.
    #[must_use]
    pub const fn with_units(mut self, value: UsageAmount) -> Self {
        self.units = value;
        self
    }

    /// Sets the tool-call count.
    #[must_use]
    pub const fn with_tool_calls(mut self, value: UsageAmount) -> Self {
        self.tool_calls = value;
        self
    }

    /// Sets the media-byte count.
    #[must_use]
    pub const fn with_media_bytes(mut self, value: UsageAmount) -> Self {
        self.media_bytes = value;
        self
    }

    /// Sets exact cost in microunits.
    #[must_use]
    pub const fn with_cost(mut self, value: CostMicrounits) -> Self {
        self.cost_microunits = value;
        self
    }

    /// Returns the request count.
    #[must_use]
    pub const fn requests(&self) -> UsageAmount {
        self.requests
    }

    /// Returns the concurrent-stream count.
    #[must_use]
    pub const fn concurrent_streams(&self) -> UsageAmount {
        self.concurrent_streams
    }

    /// Returns the aggregate token count.
    #[must_use]
    pub const fn tokens(&self) -> UsageAmount {
        self.tokens
    }

    /// Returns the provider-neutral unit count.
    #[must_use]
    pub const fn units(&self) -> UsageAmount {
        self.units
    }

    /// Returns the tool-call count.
    #[must_use]
    pub const fn tool_calls(&self) -> UsageAmount {
        self.tool_calls
    }

    /// Returns the media-byte count.
    #[must_use]
    pub const fn media_bytes(&self) -> UsageAmount {
        self.media_bytes
    }

    /// Returns exact cost in microunits.
    #[must_use]
    pub const fn cost(&self) -> CostMicrounits {
        self.cost_microunits
    }

    /// Adds every field without wrapping or saturation.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when any exact field is not representable.
    pub fn checked_add(&self, other: &Self) -> Result<Self, ArithmeticError> {
        Ok(Self {
            requests: self.requests.checked_add(other.requests)?,
            concurrent_streams: self
                .concurrent_streams
                .checked_add(other.concurrent_streams)?,
            tokens: self.tokens.checked_add(other.tokens)?,
            units: self.units.checked_add(other.units)?,
            tool_calls: self.tool_calls.checked_add(other.tool_calls)?,
            media_bytes: self.media_bytes.checked_add(other.media_bytes)?,
            cost_microunits: self.cost_microunits.checked_add(other.cost_microunits)?,
        })
    }

    /// Subtracts every field without wrapping or saturation.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when any field in `other` is greater.
    pub fn checked_sub(&self, other: &Self) -> Result<Self, ArithmeticError> {
        Ok(Self {
            requests: self.requests.checked_sub(other.requests)?,
            concurrent_streams: self
                .concurrent_streams
                .checked_sub(other.concurrent_streams)?,
            tokens: self.tokens.checked_sub(other.tokens)?,
            units: self.units.checked_sub(other.units)?,
            tool_calls: self.tool_calls.checked_sub(other.tool_calls)?,
            media_bytes: self.media_bytes.checked_sub(other.media_bytes)?,
            cost_microunits: self.cost_microunits.checked_sub(other.cost_microunits)?,
        })
    }

    /// Chooses the greater value independently for every conservative accounting field.
    #[must_use]
    pub const fn conservative_max(&self, other: &Self) -> Self {
        Self {
            requests: UsageAmount::new(max_u64(self.requests.get(), other.requests.get())),
            concurrent_streams: UsageAmount::new(max_u64(
                self.concurrent_streams.get(),
                other.concurrent_streams.get(),
            )),
            tokens: UsageAmount::new(max_u64(self.tokens.get(), other.tokens.get())),
            units: UsageAmount::new(max_u64(self.units.get(), other.units.get())),
            tool_calls: UsageAmount::new(max_u64(self.tool_calls.get(), other.tool_calls.get())),
            media_bytes: UsageAmount::new(max_u64(self.media_bytes.get(), other.media_bytes.get())),
            cost_microunits: CostMicrounits::new(max_u64(
                self.cost_microunits.get(),
                other.cost_microunits.get(),
            )),
        }
    }

    /// Clears concurrency after dispatch finishes while retaining billable usage.
    #[must_use]
    pub const fn without_concurrency(&self) -> Self {
        Self {
            requests: self.requests,
            concurrent_streams: UsageAmount::ZERO,
            tokens: self.tokens,
            units: self.units,
            tool_calls: self.tool_calls,
            media_bytes: self.media_bytes,
            cost_microunits: self.cost_microunits,
        }
    }

    /// Returns whether every field is zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.requests.get() == 0
            && self.concurrent_streams.get() == 0
            && self.tokens.get() == 0
            && self.units.get() == 0
            && self.tool_calls.get() == 0
            && self.media_bytes.get() == 0
            && self.cost_microunits.get() == 0
    }
}

/// Usage and cost split by why work occurred.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageBreakdown {
    primary: UsageVector,
    retry: UsageVector,
    repair: UsageVector,
    tool: UsageVector,
}

impl UsageBreakdown {
    /// Creates a breakdown with only primary model work.
    #[must_use]
    pub const fn primary(primary: UsageVector) -> Self {
        Self {
            primary,
            retry: UsageVector::zero(),
            repair: UsageVector::zero(),
            tool: UsageVector::zero(),
        }
    }

    /// Creates a fully attributed breakdown.
    #[must_use]
    pub const fn new(
        primary: UsageVector,
        retry: UsageVector,
        repair: UsageVector,
        tool: UsageVector,
    ) -> Self {
        Self {
            primary,
            retry,
            repair,
            tool,
        }
    }

    /// Returns primary model usage.
    #[must_use]
    pub const fn primary_usage(&self) -> &UsageVector {
        &self.primary
    }

    /// Returns retry usage.
    #[must_use]
    pub const fn retry_usage(&self) -> &UsageVector {
        &self.retry
    }

    /// Returns structured-output repair usage.
    #[must_use]
    pub const fn repair_usage(&self) -> &UsageVector {
        &self.repair
    }

    /// Returns tool execution usage.
    #[must_use]
    pub const fn tool_usage(&self) -> &UsageVector {
        &self.tool
    }

    /// Computes exact total usage without wrapping or saturation.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when any accumulated field is not representable.
    pub fn checked_total(&self) -> Result<UsageVector, ArithmeticError> {
        let total = self.primary.checked_add(&self.retry)?;
        let total = total.checked_add(&self.repair)?;
        total.checked_add(&self.tool)
    }
    pub(crate) fn includes_dispatched_request(&self) -> Result<bool, ArithmeticError> {
        Ok(self.checked_total()?.requests().get() > 0)
    }

    /// Retains the greater estimated or ambiguous observation in every attribution field.
    #[must_use]
    pub const fn conservative_max(&self, other: &Self) -> Self {
        Self {
            primary: self.primary.conservative_max(&other.primary),
            retry: self.retry.conservative_max(&other.retry),
            repair: self.repair.conservative_max(&other.repair),
            tool: self.tool.conservative_max(&other.tool),
        }
    }

    /// Clears completed concurrency while preserving attribution.
    #[must_use]
    pub const fn without_concurrency(&self) -> Self {
        Self {
            primary: self.primary.without_concurrency(),
            retry: self.retry.without_concurrency(),
            repair: self.repair.without_concurrency(),
            tool: self.tool.without_concurrency(),
        }
    }

    /// Returns whether every attributed field is zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.primary.is_zero()
            && self.retry.is_zero()
            && self.repair.is_zero()
            && self.tool.is_zero()
    }
}

/// Exact signed adjustment from one accounted breakdown to another.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageDelta {
    requests: SignedUsageAmount,
    concurrent_streams: SignedUsageAmount,
    tokens: SignedUsageAmount,
    units: SignedUsageAmount,
    tool_calls: SignedUsageAmount,
    media_bytes: SignedUsageAmount,
    cost_microunits: SignedCostMicrounits,
}

impl UsageDelta {
    /// Computes `current - previous` exactly.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] if either attributed total overflows before comparison.
    pub fn between(
        current: &UsageBreakdown,
        previous: &UsageBreakdown,
    ) -> Result<Self, ArithmeticError> {
        let current = current.checked_total()?;
        let previous = previous.checked_total()?;
        Ok(Self {
            requests: SignedUsageAmount::between(current.requests(), previous.requests()),
            concurrent_streams: SignedUsageAmount::between(
                current.concurrent_streams(),
                previous.concurrent_streams(),
            ),
            tokens: SignedUsageAmount::between(current.tokens(), previous.tokens()),
            units: SignedUsageAmount::between(current.units(), previous.units()),
            tool_calls: SignedUsageAmount::between(current.tool_calls(), previous.tool_calls()),
            media_bytes: SignedUsageAmount::between(current.media_bytes(), previous.media_bytes()),
            cost_microunits: SignedCostMicrounits::between(current.cost(), previous.cost()),
        })
    }

    /// Returns the exact signed request adjustment.
    #[must_use]
    pub const fn requests(&self) -> SignedUsageAmount {
        self.requests
    }

    /// Returns the exact signed concurrent-stream adjustment.
    #[must_use]
    pub const fn concurrent_streams(&self) -> SignedUsageAmount {
        self.concurrent_streams
    }

    /// Returns the exact signed token adjustment.
    #[must_use]
    pub const fn tokens(&self) -> SignedUsageAmount {
        self.tokens
    }

    /// Returns the exact signed unit adjustment.
    #[must_use]
    pub const fn units(&self) -> SignedUsageAmount {
        self.units
    }

    /// Returns the exact signed tool-call adjustment.
    #[must_use]
    pub const fn tool_calls(&self) -> SignedUsageAmount {
        self.tool_calls
    }

    /// Returns the exact signed media-byte adjustment.
    #[must_use]
    pub const fn media_bytes(&self) -> SignedUsageAmount {
        self.media_bytes
    }

    /// Returns the exact signed cost adjustment.
    #[must_use]
    pub const fn cost(&self) -> SignedCostMicrounits {
        self.cost_microunits
    }
}

/// Exact arithmetic could not be represented.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("exact usage arithmetic overflow or underflow")]
pub struct ArithmeticError;

const fn max_u64(left: u64, right: u64) -> u64 {
    if left >= right { left } else { right }
}
